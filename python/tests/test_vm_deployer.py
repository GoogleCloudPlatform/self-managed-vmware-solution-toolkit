"""Unit tests for vcf_deployer/vm_deployer.py module."""

import datetime
import hashlib
import io
import tarfile
import unittest
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509.oid import NameOID

import models
from vcf_deployer import vm_deployer


class TestVMDeployer(unittest.TestCase):
  """Tests for Phase 3c-f VMDeployer lifecycle operations."""

  def setUp(self):
    super().setUp()
    self.mock_esxi = mock.MagicMock()
    self.vm_dep = vm_deployer.VMDeployer(esxi=self.mock_esxi)

  def test_resolve_host_resources_success(self):
    """Verifies resolving root pool, VM folder, vSAN datastore, and port group network."""
    mock_host = mock.MagicMock()
    mock_ds = mock.MagicMock()
    mock_ds.name = "vsanDatastore"
    mock_net = mock.MagicMock()
    mock_net.name = "vlan-100-a1b2"

    mock_host.datastore = [mock_ds]
    mock_host.network = [mock_net]
    self.mock_esxi.get_host_system.return_value = mock_host
    self.mock_esxi.get_resource_pool_and_folder.return_value = (
        "pool",
        "folder",
    )

    pool, folder, ds, net = self.vm_dep._resolve_host_resources("vlan-100-a1b2")
    self.assertEqual(pool, "pool")
    self.assertEqual(folder, "folder")
    self.assertEqual(ds, mock_ds)
    self.assertEqual(net, mock_net)

  def test_resolve_host_resources_missing_datastore_raises_validation_error(
      self,
  ):
    """Verifies ValidationError when vsanDatastore is missing from host."""
    mock_host = mock.MagicMock()
    mock_host.datastore = []
    self.mock_esxi.get_host_system.return_value = mock_host
    self.mock_esxi.get_resource_pool_and_folder.return_value = (
        "pool",
        "folder",
    )

    with self.assertRaises(models.ValidationError) as ctx:
      self.vm_dep._resolve_host_resources("vlan-100-a1b2")
    self.assertIn("vsanDatastore not located on ESXi host", str(ctx.exception))

  @mock.patch.object(vm_deployer.VMDeployer, "_resolve_host_resources")
  @mock.patch.object(vm_deployer.VMDeployer, "_check_vm_exists")
  def test_deploy_ova_idempotent_existing_vm(
      self, mock_check_exists, mock_resolve_res
  ):
    """Verifies skipping OVA deployment if VirtualMachine already exists in inventory."""
    mock_existing_vm = mock.MagicMock()
    mock_check_exists.return_value = mock_existing_vm
    mock_resolve_res.return_value = ("pool", "folder", "ds", "net")

    vm_ref = self.vm_dep.deploy_ova(
        vcf_installer_ova_url="https://depot/vcf.ova",
        ssl_thumbprint="AA:BB:CC",
        port_group_name="vlan-100",
        vcf_vm_name="sddc-manager",
    )

    self.assertEqual(vm_ref, mock_existing_vm)

  def test_marshal_ovf_properties(self):
    """Verifies OVF XML property payload marshaling for vCenter-less bootstrapping."""
    xml_str = self.vm_dep._marshal_ovf_properties(
        sddc_manager_ip="10.0.0.50",
        gateway="10.0.0.1",
        netmask="255.255.255.0",
        root_pwd="RootP@ssword123!",
        local_pwd="LocalP@ssword123!",
        fqdn="sddc-manager.lab.local",
        domain="lab.local",
        searchpath="lab.local",
    )
    self.assertIn('oe:key="ROOT_PASSWORD" oe:value="RootP@ssword123!"', xml_str)
    self.assertIn(
        'oe:key="vami.hostname" oe:value="sddc-manager.lab.local"', xml_str
    )
    self.assertIn(
        'oe:key="vami.ip0.SDDC-Manager" oe:value="10.0.0.50"', xml_str
    )
    self.assertIn(
        'oe:key="vami.gateway.SDDC-Manager" oe:value="10.0.0.1"', xml_str
    )
    self.assertIn(
        'oe:key="vami.DNS.SDDC-Manager" oe:value="169.254.169.254"', xml_str
    )
    self.assertIn(
        'oe:key="guestinfo.ntp" oe:value="169.254.169.254"', xml_str
    )

    xml_str_custom_dns = self.vm_dep._marshal_ovf_properties(
        sddc_manager_ip="10.0.0.50",
        gateway="10.0.0.1",
        netmask="255.255.255.0",
        root_pwd="RootP@ssword123!",
        local_pwd="LocalP@ssword123!",
        fqdn="sddc-manager.lab.local",
        domain="lab.local",
        searchpath="lab.local",
        dns_server="10.0.0.2",
    )
    self.assertIn(
        'oe:key="vami.DNS.SDDC-Manager" oe:value="10.0.0.2"',
        xml_str_custom_dns,
    )

  @mock.patch("vcf_deployer.vm_deployer.vim")
  def test_power_on_vm_already_on(self, mock_vim):
    """Verifies skipping PowerOnVM_Task when VM is already powered on."""
    mock_vm = mock.MagicMock()
    mock_vm.runtime.powerState = mock_vim.VirtualMachinePowerState.poweredOn
    self.vm_dep._power_on_vm(mock_vm)
    mock_vm.PowerOnVM_Task.assert_not_called()

  @mock.patch.object(vm_deployer.VMDeployer, "_wait_for_task")
  def test_power_on_vm_powered_off(self, mock_wait_task):
    """Verifies PowerOnVM_Task execution when VM is powered off."""
    mock_vm = mock.MagicMock()
    mock_vm.runtime.powerState = "poweredOff"
    mock_task = mock.MagicMock()
    mock_vm.PowerOnVM_Task.return_value = mock_task

    self.vm_dep._power_on_vm(mock_vm)
    mock_vm.PowerOnVM_Task.assert_called_once()
    mock_wait_task.assert_called_once_with(mock_task)

  def test_poll_for_guest_ip_success(self):
    """Verifies polling VMware Tools guest IP telemetry matching target static IP."""
    mock_vm = mock.MagicMock()
    mock_vm.guest.ipAddress = "10.0.0.50"

    # Should succeed without raising exception
    self.vm_dep._poll_for_guest_ip(
        vm_reference=mock_vm,
        target_ip="10.0.0.50",
        poll_interval_seconds=0.01,
        timeout_seconds=1.0,
    )

  def test_poll_for_guest_ip_timeout_raises_retryable_error(self):
    """Verifies RetryableError when guest IP fails to match target IP within timeout."""
    mock_vm = mock.MagicMock()
    mock_vm.guest.ipAddress = "169.254.0.1"

    with self.assertRaises(models.RetryableError) as ctx:
      self.vm_dep._poll_for_guest_ip(
          vm_reference=mock_vm,
          target_ip="10.0.0.50",
          poll_interval_seconds=0.05,
          timeout_seconds=0.1,
      )
    self.assertIn(
        "Timed out after 0.1s waiting for guest to acquire IP",
        str(ctx.exception),
    )

  @mock.patch("vcf_deployer.vm_deployer.vim")
  def test_check_vm_exists(self, mock_vim):
    """Verifies checking VM existence in ESXi inventory viewManager container."""
    mock_vim.VirtualMachine = "VirtualMachine"
    mock_si = mock.MagicMock()
    self.mock_esxi.connect_pyvmomi.return_value = mock_si
    mock_vm = mock.MagicMock()
    mock_vm.name = "sddc-manager"
    mock_container = mock.MagicMock()
    mock_container.view = [mock_vm]
    mock_si.RetrieveContent.return_value.viewManager.CreateContainerView.return_value = (
        mock_container
    )

    vm_found = self.vm_dep._check_vm_exists("sddc-manager")
    self.assertEqual(vm_found, mock_vm)
    mock_container.Destroy.assert_called_once()

    # Check when VM does not exist
    mock_container.view = []
    vm_not_found = self.vm_dep._check_vm_exists("non-existent-vm")
    self.assertIsNone(vm_not_found)

  def test_wait_for_task_success(self):
    """Verifies waiting for pyVmomi task that completes with 'success' state."""
    mock_task = mock.MagicMock()
    mock_task.info.state = "success"
    self.vm_dep._wait_for_task(mock_task, timeout_seconds=1)

  def test_wait_for_task_error_raises_deployer_error(self):
    """Verifies DeployerError when pyVmomi task completes with 'error' state."""
    mock_task = mock.MagicMock()
    mock_task.info.state = "error"
    mock_task.info.error.localizedMessage = "Invalid OVF Property"
    with self.assertRaises(models.DeployerError) as ctx:
      self.vm_dep._wait_for_task(mock_task, timeout_seconds=1)
    self.assertIn("Task failed: Invalid OVF Property", str(ctx.exception))

  def test_wait_for_task_timeout_raises_retryable_error(self):
    """Verifies RetryableError when task polling times out."""
    mock_task = mock.MagicMock()
    mock_task.info.state = "running"
    with self.assertRaises(models.RetryableError) as ctx:
      self.vm_dep._wait_for_task(mock_task, timeout_seconds=0.01)
    self.assertIn("Timed out waiting for task completion", str(ctx.exception))

  @mock.patch("vcf_deployer.vm_deployer.vim")
  def test_wait_for_nfc_lease_ready_success(self, mock_vim):
    """Verifies waiting for NFC lease to reach ready state."""
    mock_lease = mock.MagicMock()
    mock_lease.state = mock_vim.HttpNfcLease.State.ready
    self.vm_dep._wait_for_nfc_lease_ready(mock_lease, timeout_seconds=1)

  @mock.patch("vcf_deployer.vm_deployer.vim")
  def test_wait_for_nfc_lease_ready_error_raises_deployer_error(self, mock_vim):
    """Verifies DeployerError when NFC lease reaches error state."""
    mock_lease = mock.MagicMock()
    mock_lease.state = mock_vim.HttpNfcLease.State.error
    mock_lease.error.localizedMessage = "Disk storage full"
    with self.assertRaises(models.DeployerError) as ctx:
      self.vm_dep._wait_for_nfc_lease_ready(mock_lease, timeout_seconds=1)
    self.assertIn("NFC lease failed: Disk storage full", str(ctx.exception))

  @mock.patch("vcf_deployer.vm_deployer.vim")
  @mock.patch.object(vm_deployer.VMDeployer, "_wait_for_task")
  def test_inject_guestinfo(self, mock_wait_task, mock_vim):
    """Verifies injecting OVF XML payload via ReconfigVM_Task."""
    mock_vm = mock.MagicMock()
    mock_task = mock.MagicMock()
    mock_vm.ReconfigVM_Task.return_value = mock_task

    self.vm_dep._inject_guestinfo(mock_vm, "<Environment></Environment>")
    mock_vm.ReconfigVM_Task.assert_called_once()
    mock_wait_task.assert_called_once_with(mock_task)

  @mock.patch.object(vm_deployer.VMDeployer, "_inject_guestinfo")
  def test_configure_ovf_environment(self, mock_inject):
    """Verifies Phase 3d configure_ovf_environment orchestrator with default metadata DNS."""
    mock_vm = mock.MagicMock()
    self.vm_dep.configure_ovf_environment(
        vm_reference=mock_vm,
        sddc_manager_ip="10.0.0.50",
        gateway="10.0.0.1",
        netmask="255.255.255.0",
        root_pwd="RootP@ssword123!",
        local_pwd="LocalP@ssword123!",
        fqdn="sddc-manager.lab.local",
        domain="lab.local",
        searchpath="lab.local",
    )
    mock_inject.assert_called_once()
    payload = mock_inject.call_args[0][1]
    self.assertIn(
        'oe:key="vami.DNS.SDDC-Manager" oe:value="169.254.169.254"', payload
    )
    self.assertIn(
        'oe:key="guestinfo.ntp" oe:value="169.254.169.254"', payload
    )

  @mock.patch.object(vm_deployer.VMDeployer, "_inject_guestinfo")
  def test_configure_ovf_environment_with_custom_dns_server(self, mock_inject):
    """Verifies Phase 3d configure_ovf_environment orchestrator with custom DNS server."""
    mock_vm = mock.MagicMock()
    self.vm_dep.configure_ovf_environment(
        vm_reference=mock_vm,
        sddc_manager_ip="10.0.0.50",
        gateway="10.0.0.1",
        netmask="255.255.255.0",
        root_pwd="RootP@ssword123!",
        local_pwd="LocalP@ssword123!",
        fqdn="sddc-manager.lab.local",
        domain="lab.local",
        searchpath="lab.local",
        dns_server="10.0.0.2",
    )
    mock_inject.assert_called_once()
    payload = mock_inject.call_args[0][1]
    self.assertIn(
        'oe:key="vami.DNS.SDDC-Manager" oe:value="10.0.0.2"', payload
    )
    self.assertIn(
        'oe:key="guestinfo.ntp" oe:value="169.254.169.254"', payload
    )

  @mock.patch.object(vm_deployer.VMDeployer, "_poll_for_guest_ip")
  @mock.patch.object(vm_deployer.VMDeployer, "_power_on_vm")
  def test_power_on_and_wait_for_ip(self, mock_power_on, mock_poll_ip):
    """Verifies Phase 3e power_on_and_wait_for_ip orchestrator."""
    mock_vm = mock.MagicMock()
    self.vm_dep.power_on_and_wait_for_ip(
        vm_reference=mock_vm, target_ip="10.0.0.50"
    )
    mock_power_on.assert_called_once_with(mock_vm)
    mock_poll_ip.assert_called_once_with(
        vm_reference=mock_vm,
        target_ip="10.0.0.50",
        poll_interval_seconds=10,
        timeout_seconds=600,
    )

  def test_poll_for_guest_ip_matching_net_interfaces(self):
    """Verifies matching target IP in guest interfaces array."""
    mock_vm = mock.MagicMock()
    mock_vm.guest.ipAddress = "169.254.0.1"
    mock_net_if = mock.MagicMock()
    mock_net_if.ipAddress = ["10.0.0.50"]
    mock_vm.guest.net = [mock_net_if]

    self.vm_dep._poll_for_guest_ip(
        vm_reference=mock_vm,
        target_ip="10.0.0.50",
        poll_interval_seconds=0.01,
        timeout_seconds=0.5,
    )

  @mock.patch("tarfile.open")
  @mock.patch("urllib.request.urlopen")
  def test_fetch_and_parse_ovf_descriptor_success(
      self, mock_urlopen, mock_tar_open
  ):
    """Verifies streaming TAR headers over HTTP to extract .ovf XML descriptor."""
    mock_resp = mock.MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__.return_value = mock_resp
    mock_urlopen.return_value = mock_resp

    mock_tar = mock.MagicMock()
    mock_member = mock.MagicMock()
    mock_member.isfile.return_value = True
    mock_member.name = "vcf-appliance.ovf"
    mock_tar.__iter__.return_value = [mock_member]
    mock_ovf_file = mock.MagicMock()
    mock_ovf_file.read.return_value = b"<Envelope></Envelope>"
    mock_tar.extractfile.return_value = mock_ovf_file
    mock_tar.__enter__.return_value = mock_tar
    mock_tar_open.return_value = mock_tar

    ovf_xml = self.vm_dep._fetch_and_parse_ovf_descriptor(
        "https://offline-depot.lab.local/vcf.ova",
        allow_unverified_ova=True,
    )
    self.assertEqual(ovf_xml, "<Envelope></Envelope>")

  @mock.patch("tarfile.open")
  @mock.patch("urllib.request.urlopen")
  def test_fetch_and_parse_ovf_descriptor_unverified_ova_fails_closed(
      self, mock_urlopen, mock_tar_open
  ):
    """Verifies NonRetryableError when neither depot SHA-256 nor .cert signature is present."""
    mock_resp = mock.MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__.return_value = mock_resp
    mock_urlopen.return_value = mock_resp

    mock_tar = mock.MagicMock()
    mock_member = mock.MagicMock()
    mock_member.isfile.return_value = True
    mock_member.name = "vcf-appliance.ovf"
    mock_tar.__iter__.return_value = [mock_member]
    mock_ovf_file = mock.MagicMock()
    mock_ovf_file.read.return_value = b"<Envelope></Envelope>"
    mock_tar.extractfile.return_value = mock_ovf_file
    mock_tar.__enter__.return_value = mock_tar
    mock_tar_open.return_value = mock_tar

    with self.assertRaises(models.NonRetryableError) as ctx:
      self.vm_dep._fetch_and_parse_ovf_descriptor(
          "https://offline-depot.lab.local/vcf.ova"
      )
    self.assertIn(
        "neither a verified depot SHA-256 digest nor a trusted X.509 .cert",
        str(ctx.exception),
    )

  @mock.patch("urllib.request.urlopen")
  def test_fetch_and_parse_ovf_descriptor_http_non_200_raises_non_retryable(
      self, mock_urlopen
  ):
    """Verifies NonRetryableError when HTTP status is non-200."""
    mock_resp = mock.MagicMock()
    mock_resp.status = 404
    mock_resp.__enter__.return_value = mock_resp
    mock_urlopen.return_value = mock_resp

    with self.assertRaises(models.NonRetryableError) as ctx:
      self.vm_dep._fetch_and_parse_ovf_descriptor("https://depot/vcf.ova")
    self.assertIn("HTTP fetch failed for OVF descriptor", str(ctx.exception))

  @mock.patch("vcf_deployer.vm_deployer.vim")
  @mock.patch.object(vm_deployer.VMDeployer, "_wait_for_task")
  @mock.patch.object(vm_deployer.VMDeployer, "_wait_for_nfc_lease_ready")
  def test_execute_lease_pull_success(
      self, mock_wait_nfc, mock_wait_task, mock_vim
  ):
    """Verifies creating import spec and initiating HttpNfcLeasePullFromUrls_Task."""
    mock_si = mock.MagicMock()
    self.mock_esxi.connect_pyvmomi.return_value = mock_si
    mock_ovf_mgr = mock.MagicMock()
    mock_si.RetrieveContent.return_value.ovfManager = mock_ovf_mgr
    mock_desc_result = mock.MagicMock()
    mock_desc_result.error = None
    mock_net = mock.MagicMock()
    mock_net.name = "Network 1"
    mock_desc_result.network = [mock_net]
    mock_ovf_mgr.ParseDescriptor.return_value = mock_desc_result

    mock_import_spec_res = mock.MagicMock()
    mock_import_spec_res.error = None
    mock_import_spec_res.importSpec = mock.MagicMock()
    mock_item = mock.MagicMock()
    mock_item.deviceId = "disk1"
    mock_item.path = "disk1.vmdk"
    mock_import_spec_res.fileItem = [mock_item]
    mock_ovf_mgr.CreateImportSpec.return_value = mock_import_spec_res

    mock_res_pool = mock.MagicMock()
    mock_lease = mock.MagicMock()
    mock_vm_entity = mock.MagicMock()
    mock_lease.info.entity = mock_vm_entity
    mock_res_pool.ImportVApp.return_value = mock_lease

    mock_task = mock.MagicMock()
    mock_lease.HttpNfcLeasePullFromUrls_Task.return_value = mock_task

    vm_ref = self.vm_dep._execute_lease_pull(
        ovf_descriptor="<Envelope></Envelope>",
        resource_pool=mock_res_pool,
        vm_folder=mock.MagicMock(),
        datastore=mock.MagicMock(),
        network=mock.MagicMock(),
        ova_url="https://offline-depot.lab.local/vcf.ova",
        ssl_thumbprint="AA:BB:CC",
        vcf_vm_name="sddc-manager",
    )

    self.assertEqual(vm_ref, mock_vm_entity)
    mock_wait_nfc.assert_called_once_with(mock_lease)
    mock_wait_task.assert_called_once_with(mock_task)
    mock_lease.HttpNfcLeaseComplete.assert_called_once()

  @mock.patch("vcf_deployer.vm_deployer.vim")
  @mock.patch.object(vm_deployer.VMDeployer, "_wait_for_task")
  @mock.patch.object(vm_deployer.VMDeployer, "_wait_for_nfc_lease_ready")
  def test_execute_lease_pull_task_failure_aborts_lease(
      self, mock_wait_nfc, mock_wait_task, mock_vim
  ):
    """Verifies that task failures during NFC lease pull trigger HttpNfcLeaseAbort and raise DeployerError."""
    mock_si = mock.MagicMock()
    self.mock_esxi.connect_pyvmomi.return_value = mock_si
    mock_ovf_mgr = mock.MagicMock()
    mock_si.RetrieveContent.return_value.ovfManager = mock_ovf_mgr
    mock_desc_result = mock.MagicMock()
    mock_desc_result.error = None
    mock_net = mock.MagicMock()
    mock_net.name = "Network 1"
    mock_desc_result.network = [mock_net]
    mock_ovf_mgr.ParseDescriptor.return_value = mock_desc_result

    mock_import_spec_res = mock.MagicMock()
    mock_import_spec_res.error = None
    mock_import_spec_res.importSpec = mock.MagicMock()
    mock_import_spec_res.fileItem = []
    mock_ovf_mgr.CreateImportSpec.return_value = mock_import_spec_res

    mock_res_pool = mock.MagicMock()
    mock_lease = mock.MagicMock()
    mock_res_pool.ImportVApp.return_value = mock_lease

    mock_task = mock.MagicMock()
    mock_lease.HttpNfcLeasePullFromUrls_Task.return_value = mock_task
    mock_wait_task.side_effect = models.DeployerError("Storage write failure")

    with self.assertRaises(models.DeployerError) as ctx:
      self.vm_dep._execute_lease_pull(
          ovf_descriptor="<Envelope></Envelope>",
          resource_pool=mock_res_pool,
          vm_folder=mock.MagicMock(),
          datastore=mock.MagicMock(),
          network=mock.MagicMock(),
          ova_url="https://offline-depot.lab.local/vcf.ova",
          ssl_thumbprint="AA:BB:CC",
          vcf_vm_name="sddc-manager",
      )

    self.assertIn(
        "NFC lease pull task failed for VM 'sddc-manager'", str(ctx.exception)
    )
    mock_lease.HttpNfcLeaseAbort.assert_called_once()
    mock_lease.HttpNfcLeaseComplete.assert_not_called()

  @mock.patch("vcf_deployer.vm_deployer.vim")
  @mock.patch.object(vm_deployer.VMDeployer, "_check_vm_exists")
  @mock.patch.object(vm_deployer.VMDeployer, "_wait_for_task")
  @mock.patch.object(vm_deployer.VMDeployer, "_wait_for_nfc_lease_ready")
  def test_execute_lease_pull_unresolved_vm_reference(
      self, mock_wait_nfc, mock_wait_task, mock_check_vm, mock_vim
  ):
    """Verifies DeployerError when created VM reference cannot be resolved."""
    mock_si = mock.MagicMock()
    self.mock_esxi.connect_pyvmomi.return_value = mock_si
    mock_ovf_mgr = mock.MagicMock()
    mock_si.RetrieveContent.return_value.ovfManager = mock_ovf_mgr
    mock_desc_result = mock.MagicMock()
    mock_desc_result.error = None
    mock_net = mock.MagicMock()
    mock_net.name = "Network 1"
    mock_desc_result.network = [mock_net]
    mock_ovf_mgr.ParseDescriptor.return_value = mock_desc_result

    mock_import_spec_res = mock.MagicMock()
    mock_import_spec_res.error = None
    mock_import_spec_res.importSpec = mock.MagicMock()
    mock_import_spec_res.fileItem = []
    mock_ovf_mgr.CreateImportSpec.return_value = mock_import_spec_res

    mock_res_pool = mock.MagicMock()
    mock_lease = mock.MagicMock()
    mock_lease.info = None
    mock_res_pool.ImportVApp.return_value = mock_lease
    mock_check_vm.return_value = None

    with self.assertRaises(models.DeployerError) as ctx:
      self.vm_dep._execute_lease_pull(
          ovf_descriptor="<Envelope></Envelope>",
          resource_pool=mock_res_pool,
          vm_folder=mock.MagicMock(),
          datastore=mock.MagicMock(),
          network=mock.MagicMock(),
          ova_url="https://offline-depot.lab.local/vcf.ova",
          ssl_thumbprint="AA:BB:CC",
          vcf_vm_name="sddc-manager",
      )

    self.assertIn(
        "Failed to resolve created VirtualMachine reference for 'sddc-manager'",
        str(ctx.exception),
    )

  @mock.patch("vcf_deployer.vm_deployer.vim")
  def test_execute_lease_pull_missing_networks_raises_non_retryable(
      self, mock_vim
  ):
    """Verifies NonRetryableError when ParseDescriptor returns no logical networks."""
    mock_si = mock.MagicMock()
    self.mock_esxi.connect_pyvmomi.return_value = mock_si
    mock_ovf_mgr = mock.MagicMock()
    mock_si.RetrieveContent.return_value.ovfManager = mock_ovf_mgr

    mock_desc_result = mock.MagicMock()
    mock_desc_result.error = "Parse error"
    mock_desc_result.network = None
    mock_ovf_mgr.ParseDescriptor.return_value = mock_desc_result

    with self.assertRaises(models.NonRetryableError) as ctx:
      self.vm_dep._execute_lease_pull(
          ovf_descriptor="<Envelope></Envelope>",
          resource_pool=mock.MagicMock(),
          vm_folder=mock.MagicMock(),
          datastore=mock.MagicMock(),
          network=mock.MagicMock(),
          ova_url="https://offline-depot.lab.local/vcf.ova",
          ssl_thumbprint="AA:BB:CC",
          vcf_vm_name="sddc-manager",
      )
    self.assertIn("No logical networks found in OVF descriptor", str(ctx.exception))

  @mock.patch("vcf_deployer.vm_deployer.vim")
  @mock.patch.object(vm_deployer.VMDeployer, "_wait_for_task")
  @mock.patch.object(vm_deployer.VMDeployer, "_wait_for_nfc_lease_ready")
  def test_execute_lease_pull_dynamic_network_parsing(
      self, mock_wait_nfc, mock_wait_task, mock_vim
  ):
    """Verifies dynamic extraction of network names from OVF descriptor via ParseDescriptor."""
    mock_si = mock.MagicMock()
    self.mock_esxi.connect_pyvmomi.return_value = mock_si
    mock_ovf_mgr = mock.MagicMock()
    mock_si.RetrieveContent.return_value.ovfManager = mock_ovf_mgr
    mock_vim.OvfManager.NetworkMapping.side_effect = lambda: mock.MagicMock()

    mock_net_info1 = mock.MagicMock()
    mock_net_info1.name = "Deployment Network"
    mock_net_info2 = mock.MagicMock()
    mock_net_info2.name = "Management Network"

    mock_desc_result = mock.MagicMock()
    mock_desc_result.error = None
    mock_desc_result.network = [mock_net_info1, mock_net_info2]
    mock_ovf_mgr.ParseDescriptor.return_value = mock_desc_result

    mock_import_spec_res = mock.MagicMock()
    mock_import_spec_res.error = None
    mock_import_spec_res.importSpec = mock.MagicMock()
    mock_import_spec_res.fileItem = []
    mock_ovf_mgr.CreateImportSpec.return_value = mock_import_spec_res

    mock_res_pool = mock.MagicMock()
    mock_lease = mock.MagicMock()
    mock_vm_entity = mock.MagicMock()
    mock_lease.info.entity = mock_vm_entity
    mock_res_pool.ImportVApp.return_value = mock_lease

    mock_net_ref = mock.MagicMock()

    self.vm_dep._execute_lease_pull(
        ovf_descriptor="<Envelope><NetworkSection/></Envelope>",
        resource_pool=mock_res_pool,
        vm_folder=mock.MagicMock(),
        datastore=mock.MagicMock(),
        network=mock_net_ref,
        ova_url="https://offline-depot.lab.local/vcf.ova",
        ssl_thumbprint="AA:BB:CC",
        vcf_vm_name="sddc-manager",
    )

    mock_ovf_mgr.ParseDescriptor.assert_called_once()
    create_spec_call = mock_ovf_mgr.CreateImportSpec.call_args[0]
    passed_params = create_spec_call[3]
    self.assertEqual(len(passed_params.networkMapping), 2)
    self.assertEqual(passed_params.networkMapping[0].name, "Deployment Network")
    self.assertEqual(passed_params.networkMapping[1].name, "Management Network")
    self.assertEqual(passed_params.networkMapping[0].network, mock_net_ref)
    self.assertEqual(passed_params.networkMapping[1].network, mock_net_ref)

  @mock.patch.object(vm_deployer.VMDeployer, "_execute_lease_pull")
  @mock.patch.object(vm_deployer.VMDeployer, "_fetch_and_parse_ovf_descriptor")
  @mock.patch.object(vm_deployer.VMDeployer, "_check_vm_exists")
  @mock.patch.object(vm_deployer.VMDeployer, "_resolve_host_resources")
  def test_deploy_ova_full_flow(
      self, mock_resolve, mock_check, mock_fetch_ovf, mock_execute_pull
  ):
    """Verifies full Phase 3c deploy_ova flow when VM does not exist."""
    mock_resolve.return_value = ("pool", "folder", "ds", "net")
    mock_check.return_value = None
    mock_fetch_ovf.return_value = "<Envelope></Envelope>"
    mock_created_vm = mock.MagicMock()
    mock_execute_pull.return_value = mock_created_vm

    vm_ref = self.vm_dep.deploy_ova(
        vcf_installer_ova_url="https://depot/vcf.ova",
        ssl_thumbprint="AA:BB:CC",
        port_group_name="vlan-100",
        vcf_vm_name="sddc-manager",
    )

    self.assertEqual(vm_ref, mock_created_vm)
    mock_fetch_ovf.assert_called_once_with(
        "https://depot/vcf.ova",
        expected_ova_sha256=None,
        require_signature=False,
        ssl_thumbprint="AA:BB:CC",
    )
    mock_execute_pull.assert_called_once()


  # ============================================================================
  # OVA Integrity (.mf Manifest, .cert X.509 Signature, and SHA-256) Tests
  # ============================================================================

  @staticmethod
  def _build_signed_ova_bytes(
      ovf_bytes: bytes = b"<Envelope><NetworkSection/></Envelope>",
      vmdk_bytes: bytes = b"dummy-vmdk-disk-content",
      use_ecdsa: bool = False,
      expired_cert: bool = False,
      self_signed_leaf: bool = False,
      include_codesigning_eku: bool = True,
      include_intermediate_ca: bool = False,
      sig_algo_name: str = "SHA256",
      mf_at_end: bool = False,
      extra_unlisted_vmdk: bool = False,
      missing_manifest_file: bool = False,
      tamper_ovf_after_manifest: bool = False,
      tamper_mf_after_sign: bool = False,
      include_mf: bool = True,
      include_cert: bool = True,
  ) -> tuple[bytes, str]:
    """Builds an in-memory OVA TAR archive with .ovf, .mf, .cert, and .vmdk, plus Root CA PEM."""
    ovf_name = "vcf-appliance.ovf"
    vmdk_name = "vcf-appliance-disk1.vmdk"
    mf_name = "vcf-appliance.mf"
    cert_name = "vcf-appliance.cert"

    ovf_sha256 = hashlib.sha256(ovf_bytes).hexdigest()
    vmdk_sha256 = hashlib.sha256(vmdk_bytes).hexdigest()
    mf_lines = [
        f"SHA256({ovf_name})= {ovf_sha256}",
        f"SHA256({vmdk_name})= {vmdk_sha256}",
    ]
    if missing_manifest_file:
      mf_lines.append(f"SHA256(missing-disk2.vmdk)= {'a' * 64}")
    mf_content = ("\n".join(mf_lines) + "\n").encode("utf-8")

    now = datetime.datetime.now(datetime.timezone.utc)
    ca_not_before = now - datetime.timedelta(days=30)
    ca_not_after = now + datetime.timedelta(days=365)

    # 1. Generate Root CA
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "VMware VCF Test Root CA"),
    ])
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_subject)
        .issuer_name(root_subject)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(ca_not_before)
        .not_valid_after(ca_not_after)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(root_key, hashes.SHA256())
    )
    root_ca_pem = root_cert.public_bytes(serialization.Encoding.PEM).decode(
        "utf-8"
    )

    issuer_key = root_key
    issuer_subject = root_subject
    intermediate_pem = ""
    if include_intermediate_ca:
      inter_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
      inter_subject = x509.Name([
          x509.NameAttribute(
              NameOID.COMMON_NAME, "VMware VCF Test Intermediate CA"
          ),
      ])
      inter_cert = (
          x509.CertificateBuilder()
          .subject_name(inter_subject)
          .issuer_name(root_subject)
          .public_key(inter_key.public_key())
          .serial_number(x509.random_serial_number())
          .not_valid_before(ca_not_before)
          .not_valid_after(ca_not_after)
          .add_extension(
              x509.BasicConstraints(ca=True, path_length=0), critical=True
          )
          .add_extension(
              x509.KeyUsage(
                  digital_signature=True,
                  content_commitment=False,
                  key_encipherment=False,
                  data_encipherment=False,
                  key_agreement=False,
                  key_cert_sign=True,
                  crl_sign=True,
                  encipher_only=False,
                  decipher_only=False,
              ),
              critical=True,
          )
          .sign(root_key, hashes.SHA256())
      )
      intermediate_pem = inter_cert.public_bytes(
          serialization.Encoding.PEM
      ).decode("utf-8")
      issuer_key = inter_key
      issuer_subject = inter_subject

    # 2. Generate Leaf Code-Signing Certificate
    if use_ecdsa:
      leaf_key = ec.generate_private_key(ec.SECP256R1())
    else:
      leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    leaf_subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "VMware VCF Test Signer"),
    ])
    if expired_cert:
      not_before = now - datetime.timedelta(days=10)
      not_after = now - datetime.timedelta(days=1)
    else:
      not_before = now - datetime.timedelta(days=1)
      not_after = now + datetime.timedelta(days=30)

    effective_issuer_subject = (
        leaf_subject if self_signed_leaf else issuer_subject
    )
    effective_signing_key = leaf_key if self_signed_leaf else issuer_key

    leaf_builder = (
        x509.CertificateBuilder()
        .subject_name(leaf_subject)
        .issuer_name(effective_issuer_subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    if include_codesigning_eku:
      leaf_builder = leaf_builder.add_extension(
          x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),
          critical=False,
      )
    else:
      leaf_builder = leaf_builder.add_extension(
          x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
          critical=False,
      )

    leaf_cert = leaf_builder.sign(effective_signing_key, hashes.SHA256())
    pem_cert = leaf_cert.public_bytes(serialization.Encoding.PEM).decode(
        "utf-8"
    )
    if intermediate_pem:
      pem_cert = pem_cert + intermediate_pem

    sig_hash_obj = (
        hashes.SHA1() if sig_algo_name == "SHA1" else hashes.SHA256()
    )
    if use_ecdsa:
      sig_bytes = leaf_key.sign(mf_content, ec.ECDSA(sig_hash_obj))
    else:
      sig_bytes = leaf_key.sign(
          mf_content, padding.PKCS1v15(), sig_hash_obj
      )
    cert_content = (
        f"{sig_algo_name}({mf_name})= {sig_bytes.hex()}\n{pem_cert}"
    ).encode("utf-8")

    if tamper_ovf_after_manifest:
      ovf_bytes = b"<Envelope><Tampered/></Envelope>"
    if tamper_mf_after_sign:
      mf_content = (
          f"SHA256({ovf_name})= {'0' * 64}\n"
          f"SHA256({vmdk_name})= {vmdk_sha256}\n"
      ).encode("utf-8")

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
      items = [(ovf_name, ovf_bytes)]
      if not mf_at_end:
        if include_mf:
          items.append((mf_name, mf_content))
        if include_cert:
          items.append((cert_name, cert_content))
      items.append((vmdk_name, vmdk_bytes))
      if extra_unlisted_vmdk:
        items.append(("injected-unlisted.vmdk", b"rogue-disk-payload"))
      if mf_at_end:
        if include_mf:
          items.append((mf_name, mf_content))
        if include_cert:
          items.append((cert_name, cert_content))
      for name, data in items:
        info = tarfile.TarInfo(name=name)
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue(), root_ca_pem

  @mock.patch("urllib.request.urlopen")
  def test_fetch_and_parse_ovf_descriptor_with_valid_manifest_and_rsa_cert(
      self, mock_urlopen
  ):
    """Verifies OVA with valid .mf digest and CA-trusted RSA .cert signature passes verification."""
    ova_bytes, root_ca_pem = self._build_signed_ova_bytes()
    mock_resp = io.BytesIO(ova_bytes)
    mock_resp.status = 200
    mock_urlopen.return_value = mock_resp

    ovf_xml = self.vm_dep._fetch_and_parse_ovf_descriptor(
        "https://offline-depot.lab.local/vcf.ova",
        require_signature=True,
        trusted_ca_pem=root_ca_pem,
    )
    self.assertEqual(ovf_xml, "<Envelope><NetworkSection/></Envelope>")

  @mock.patch("urllib.request.urlopen")
  def test_fetch_and_parse_ovf_descriptor_with_valid_manifest_and_ecdsa_cert(
      self, mock_urlopen
  ):
    """Verifies OVA with valid .mf digest and CA-trusted ECDSA .cert signature passes verification."""
    ova_bytes, root_ca_pem = self._build_signed_ova_bytes(use_ecdsa=True)
    mock_resp = io.BytesIO(ova_bytes)
    mock_resp.status = 200
    mock_urlopen.return_value = mock_resp

    ovf_xml = self.vm_dep._fetch_and_parse_ovf_descriptor(
        "https://offline-depot.lab.local/vcf.ova",
        require_signature=True,
        trusted_ca_pem=root_ca_pem,
    )
    self.assertEqual(ovf_xml, "<Envelope><NetworkSection/></Envelope>")

  @mock.patch("urllib.request.urlopen")
  def test_fetch_and_parse_ovf_descriptor_intermediate_ca_chain_success(
      self, mock_urlopen
  ):
    """Verifies 3-tier X.509 chain (Root CA -> Intermediate CA -> Leaf CodeSigning) passes verification."""
    ova_bytes, root_ca_pem = self._build_signed_ova_bytes(
        include_intermediate_ca=True
    )
    mock_resp = io.BytesIO(ova_bytes)
    mock_resp.status = 200
    mock_urlopen.return_value = mock_resp

    ovf_xml = self.vm_dep._fetch_and_parse_ovf_descriptor(
        "https://offline-depot.lab.local/vcf.ova",
        require_signature=True,
        trusted_ca_pem=root_ca_pem,
    )
    self.assertEqual(ovf_xml, "<Envelope><NetworkSection/></Envelope>")

  @mock.patch("urllib.request.urlopen")
  def test_fetch_and_parse_ovf_descriptor_untrusted_self_signed_cert_raises(
      self, mock_urlopen
  ):
    """Verifies NonRetryableError when .cert contains an untrusted self-signed certificate."""
    ova_bytes, root_ca_pem = self._build_signed_ova_bytes(
        self_signed_leaf=True
    )
    mock_resp = io.BytesIO(ova_bytes)
    mock_resp.status = 200
    mock_urlopen.return_value = mock_resp

    with self.assertRaises(models.NonRetryableError) as ctx:
      self.vm_dep._fetch_and_parse_ovf_descriptor(
          "https://offline-depot.lab.local/vcf.ova",
          trusted_ca_pem=root_ca_pem,
      )
    self.assertIn(
        "OVA signing certificate chain is untrusted", str(ctx.exception)
    )

  @mock.patch("urllib.request.urlopen")
  def test_fetch_and_parse_ovf_descriptor_missing_codesigning_eku_raises(
      self, mock_urlopen
  ):
    """Verifies NonRetryableError when leaf certificate lacks ExtendedKeyUsage(codeSigning)."""
    ova_bytes, root_ca_pem = self._build_signed_ova_bytes(
        include_codesigning_eku=False
    )
    mock_resp = io.BytesIO(ova_bytes)
    mock_resp.status = 200
    mock_urlopen.return_value = mock_resp

    with self.assertRaises(models.NonRetryableError) as ctx:
      self.vm_dep._fetch_and_parse_ovf_descriptor(
          "https://offline-depot.lab.local/vcf.ova",
          trusted_ca_pem=root_ca_pem,
      )
    self.assertIn("ExtendedKeyUsage", str(ctx.exception))

  @mock.patch("urllib.request.urlopen")
  def test_fetch_and_parse_ovf_descriptor_sha1_cert_signature_rejected(
      self, mock_urlopen
  ):
    """Verifies NonRetryableError when .cert uses weak SHA1 signature digest."""
    ova_bytes, root_ca_pem = self._build_signed_ova_bytes(
        sig_algo_name="SHA1"
    )
    mock_resp = io.BytesIO(ova_bytes)
    mock_resp.status = 200
    mock_urlopen.return_value = mock_resp

    with self.assertRaises(models.NonRetryableError) as ctx:
      self.vm_dep._fetch_and_parse_ovf_descriptor(
          "https://offline-depot.lab.local/vcf.ova",
          trusted_ca_pem=root_ca_pem,
      )
    self.assertIn(
        "Unsupported or weak signature digest algorithm", str(ctx.exception)
    )

  @mock.patch("urllib.request.urlopen")
  def test_fetch_and_parse_ovf_descriptor_manifest_mismatch_raises_non_retryable(
      self, mock_urlopen
  ):
    """Verifies NonRetryableError when .ovf content does not match .mf SHA-256 digest."""
    ova_bytes, root_ca_pem = self._build_signed_ova_bytes(
        tamper_ovf_after_manifest=True
    )
    mock_resp = io.BytesIO(ova_bytes)
    mock_resp.status = 200
    mock_urlopen.return_value = mock_resp

    with self.assertRaises(models.NonRetryableError) as ctx:
      self.vm_dep._fetch_and_parse_ovf_descriptor(
          "https://offline-depot.lab.local/vcf.ova",
          trusted_ca_pem=root_ca_pem,
      )
    self.assertIn("OVA manifest (.mf) SHA256 hash mismatch", str(ctx.exception))

  @mock.patch("urllib.request.urlopen")
  def test_fetch_and_parse_ovf_descriptor_missing_file_in_manifest_raises(
      self, mock_urlopen
  ):
    """Verifies NonRetryableError when a file listed in .mf is missing from the TAR archive."""
    ova_bytes, root_ca_pem = self._build_signed_ova_bytes(
        missing_manifest_file=True
    )
    mock_resp = io.BytesIO(ova_bytes)
    mock_resp.status = 200
    mock_urlopen.return_value = mock_resp

    with self.assertRaises(models.NonRetryableError) as ctx:
      self.vm_dep._fetch_and_parse_ovf_descriptor(
          "https://offline-depot.lab.local/vcf.ova",
          trusted_ca_pem=root_ca_pem,
      )
    self.assertIn(
        "OVA archive is missing file 'missing-disk2.vmdk'", str(ctx.exception)
    )

  @mock.patch("urllib.request.urlopen")
  def test_fetch_and_parse_ovf_descriptor_unlisted_file_in_archive_raises(
      self, mock_urlopen
  ):
    """Verifies NonRetryableError when TAR archive contains a file not listed in .mf."""
    ova_bytes, root_ca_pem = self._build_signed_ova_bytes(
        extra_unlisted_vmdk=True
    )
    mock_resp = io.BytesIO(ova_bytes)
    mock_resp.status = 200
    mock_urlopen.return_value = mock_resp

    with self.assertRaises(models.NonRetryableError) as ctx:
      self.vm_dep._fetch_and_parse_ovf_descriptor(
          "https://offline-depot.lab.local/vcf.ova",
          trusted_ca_pem=root_ca_pem,
      )
    self.assertIn(
        "not listed in manifest (.mf)", str(ctx.exception)
    )

  @mock.patch("urllib.request.urlopen")
  def test_fetch_and_parse_ovf_descriptor_mf_and_cert_at_end_of_archive_dsp0243(
      self, mock_urlopen
  ):
    """Verifies DSP0243 TAR ordering where .mf and .cert appear after .vmdk."""
    ova_bytes, root_ca_pem = self._build_signed_ova_bytes(mf_at_end=True)
    mock_resp = io.BytesIO(ova_bytes)
    mock_resp.status = 200
    mock_urlopen.return_value = mock_resp

    ovf_xml = self.vm_dep._fetch_and_parse_ovf_descriptor(
        "https://offline-depot.lab.local/vcf.ova",
        require_signature=True,
        trusted_ca_pem=root_ca_pem,
    )
    self.assertEqual(ovf_xml, "<Envelope><NetworkSection/></Envelope>")

  @mock.patch("urllib.request.urlopen")
  def test_fetch_and_parse_ovf_descriptor_invalid_signature_raises_non_retryable(
      self, mock_urlopen
  ):
    """Verifies NonRetryableError when .mf signature in .cert fails cryptographic verification."""
    escaped_ovf = b"<Envelope><NetworkSection/></Envelope>"
    ova_bytes, root_ca_pem = self._build_signed_ova_bytes(
        ovf_bytes=escaped_ovf, tamper_mf_after_sign=True
    )
    buf = io.BytesIO()
    with tarfile.open(fileobj=io.BytesIO(ova_bytes), mode="r") as src_tar:
      cert_data = src_tar.extractfile("vcf-appliance.cert").read()
    tampered_ovf = b"<Envelope><Modified/></Envelope>"
    tampered_mf = (
        f"SHA256(vcf-appliance.ovf)= {hashlib.sha256(tampered_ovf).hexdigest()}\n"
    ).encode("utf-8")
    with tarfile.open(fileobj=buf, mode="w") as tar:
      for name, data in [
          ("vcf-appliance.ovf", tampered_ovf),
          ("vcf-appliance.mf", tampered_mf),
          ("vcf-appliance.cert", cert_data),
      ]:
        info = tarfile.TarInfo(name=name)
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))

    mock_resp = io.BytesIO(buf.getvalue())
    mock_resp.status = 200
    mock_urlopen.return_value = mock_resp

    with self.assertRaises(models.NonRetryableError) as ctx:
      self.vm_dep._fetch_and_parse_ovf_descriptor(
          "https://offline-depot.lab.local/vcf.ova",
          trusted_ca_pem=root_ca_pem,
      )
    self.assertIn(
        "OVA cryptographic signature verification failed", str(ctx.exception)
    )

  @mock.patch("urllib.request.urlopen")
  def test_fetch_and_parse_ovf_descriptor_expired_cert_raises_non_retryable(
      self, mock_urlopen
  ):
    """Verifies NonRetryableError when X.509 signing certificate in .cert is expired."""
    ova_bytes, root_ca_pem = self._build_signed_ova_bytes(expired_cert=True)
    mock_resp = io.BytesIO(ova_bytes)
    mock_resp.status = 200
    mock_urlopen.return_value = mock_resp

    with self.assertRaises(models.NonRetryableError) as ctx:
      self.vm_dep._fetch_and_parse_ovf_descriptor(
          "https://offline-depot.lab.local/vcf.ova",
          trusted_ca_pem=root_ca_pem,
      )
    self.assertIn("expired or not yet valid", str(ctx.exception))

  @mock.patch("urllib.request.urlopen")
  def test_fetch_and_parse_ovf_descriptor_expected_ova_sha256_success(
      self, mock_urlopen
  ):
    """Verifies whole-OVA SHA-256 and VMDK manifest verification when expected_ova_sha256 matches."""
    # Mirrors real VCF 9.1.1.0 OVA (.ovf + .mf + .vmdk, no .cert, verified via catalog SHA-256)
    ova_bytes, _ = self._build_signed_ova_bytes(include_cert=False)
    expected_sha256 = hashlib.sha256(ova_bytes).hexdigest()
    mock_resp = io.BytesIO(ova_bytes)
    mock_resp.status = 200
    mock_urlopen.return_value = mock_resp

    with mock.patch.object(
        self.vm_dep,
        "_compute_stream_digests",
        wraps=self.vm_dep._compute_stream_digests,
    ) as spy_stream_digests:
      ovf_xml = self.vm_dep._fetch_and_parse_ovf_descriptor(
          "https://offline-depot.lab.local/vcf.ova",
          expected_ova_sha256=expected_sha256,
      )
    self.assertEqual(ovf_xml, "<Envelope><NetworkSection/></Envelope>")
    # Verify single-algorithm SHA256 hashing was used for .vmdk stream
    spy_stream_digests.assert_called_once()
    self.assertEqual(
        spy_stream_digests.call_args.kwargs.get("algorithms"), ("SHA256",)
    )

  @mock.patch("urllib.request.urlopen")
  def test_fetch_and_parse_ovf_descriptor_expected_ova_sha256_mismatch_raises(
      self, mock_urlopen
  ):
    """Verifies NonRetryableError when whole-OVA SHA-256 does not match expected_ova_sha256."""
    ova_bytes, _ = self._build_signed_ova_bytes(include_cert=False)
    wrong_sha256 = "f" * 64
    mock_resp = io.BytesIO(ova_bytes)
    mock_resp.status = 200
    mock_urlopen.return_value = mock_resp

    with self.assertRaises(models.NonRetryableError) as ctx:
      self.vm_dep._fetch_and_parse_ovf_descriptor(
          "https://offline-depot.lab.local/vcf.ova",
          expected_ova_sha256=wrong_sha256,
      )
    self.assertIn("OVA SHA-256 integrity check failed", str(ctx.exception))

  def test_fetch_and_parse_ovf_descriptor_invalid_sha256_format_raises_validation_error(
      self,
  ):
    """Verifies ValidationError when expected_ova_sha256 is not a valid 64-char hex digest."""
    with self.assertRaises(models.ValidationError) as ctx:
      self.vm_dep._fetch_and_parse_ovf_descriptor(
          "https://offline-depot.lab.local/vcf.ova",
          expected_ova_sha256="invalid-sha256",
      )
    self.assertIn("Invalid expected_ova_sha256", str(ctx.exception))


if __name__ == "__main__":
  unittest.main()


