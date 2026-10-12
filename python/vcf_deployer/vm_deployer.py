"""VCF Installer VM Deployment and Bootstrap Orchestrator module.

Combines VCF installer VirtualMachine lifecycle operations across Phase 3c
(streaming OVA direct URL NFC lease pulling), Phase 3d (vCenter-less OVF
extraConfig environment injection via ReconfigVM_Task), Phase 3e
(idempotent power activation and guest networking telemetry polling), and
Phase 3f (VCF appliance HCL bypass).
"""

import datetime
import hashlib
import logging
import os
import re
import shlex
import ssl
import tarfile
import time
from typing import Any, Dict, List, Optional, Tuple
import urllib.parse
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID
import paramiko

from clients import esxi_client as esxi_client_mod
import constants
import models
from utils import network_utils

try:
  from pyVmomi import vim
except ImportError:
  vim = None


logger = logging.getLogger(constants.DeployerDefaults.LOGGER_NAME)


class _HashingStreamWrapper:
  """File-like wrapper that computes a running SHA-256 digest over bytes read."""

  def __init__(self, stream: Any) -> None:
    self._stream = stream
    self._sha256 = hashlib.sha256()

  def read(self, size: int = -1) -> bytes:
    chunk = self._stream.read(size)
    if chunk:
      self._sha256.update(chunk)
    return chunk

  def drain(self, chunk_size: int = 1024 * 1024) -> str:
    """Reads any remaining bytes in the stream and returns the hex digest."""
    while True:
      chunk = self.read(chunk_size)
      if not chunk:
        break
    return self._sha256.hexdigest()


class VMDeployer:
  """Unified lifecycle manager for VCF Installer VM import and bootstrapping."""

  def __init__(self, esxi: esxi_client_mod.ESXiClient) -> None:
    """Initializes VMDeployer with target ESXiClient wrapper.

    Args:
        esxi: Initialized ESXiClient connected to target hypervisor.
    """
    self.esxi = esxi

  # ============================================================================
  # Phase 3c: VCF Installer OVA Deployment
  # ============================================================================

  def deploy_ova(
      self,
      vcf_installer_ova_url: str,
      ssl_thumbprint: Optional[str],
      port_group_name: str,
      vcf_vm_name: str,
      expected_ova_sha256: Optional[str] = None,
      require_signature: bool = False,
  ) -> Any:
    """Executes Phase 3c OVA deployment onto ESXi vSAN storage inventory.

    Step A: Resource Resolution - Acquires root resource pool ('ha-root-pool'),
            root VM folder ('ha-folder-vm'), target port group, and datastore.
    Step B: Idempotency Check - Queries viewManager for existing VirtualMachine
            matching vcf_vm_name. If present, logs notice and returns reference.
    Step C: Streaming OVF Descriptor Parsing & Integrity Verification - Connects
            via HTTP stream to extract OVA archive headers (.ovf, .mf, .cert),
            verifies the manifest digest and X.509 cryptographic signature, and
            optionally verifies the full OVA SHA-256 digest.
    Step D: Direct URL NFC Lease Pull - Invokes HttpNfcLeasePullFromUrls_Task
            instructing ESXi to pull .vmdk blocks directly from remote server.

    Args:
        vcf_installer_ova_url: Remote HTTP/GCS path to VCF installer OVA file.
        ssl_thumbprint: Captured SHA-256 SSL thumbprint of remote GCS depot.
        port_group_name: Standardized virtual port group label ("vlan-<ID>").
        vcf_vm_name: Deduplicated virtual machine appliance label.
        expected_ova_sha256: Optional expected 64-char hex SHA-256 digest of the
          entire OVA file.
        require_signature: If True, fails if .mf or .cert is absent from the
          OVA archive.

    Returns:
        Managed object reference to the deployed or existing VirtualMachine.

    Raises:
        models.DeployerError: On lease pull error, missing storage, OVF fail,
          or OVA hash/signature verification failure.
    """
    logger.info(
        "Phase 3c: Starting deployment of VM '%s' from %s...",
        vcf_vm_name,
        vcf_installer_ova_url,
    )
    self.esxi.connect_pyvmomi()

    # Step A: Resource Resolution
    res_pool, vm_folder, datastore, network = self._resolve_host_resources(
        port_group_name
    )

    # Step B: Idempotency Check
    existing_vm = self._check_vm_exists(vcf_vm_name)
    if existing_vm:
      logger.info(
          "Virtual Machine '%s' already exists in inventory; skipping OVA"
          " import.",
          vcf_vm_name,
      )
      return existing_vm

    # Step C: Streaming OVF Descriptor Parsing & Integrity Verification
    logger.info(
        "Streaming OVA HTTP headers to extract and verify .ovf XML"
        " descriptor..."
    )
    ovf_xml = self._fetch_and_parse_ovf_descriptor(
        vcf_installer_ova_url,
        expected_ova_sha256=expected_ova_sha256,
        require_signature=require_signature,
        ssl_thumbprint=ssl_thumbprint,
    )

    # Step D: Direct URL NFC Lease Pull
    logger.info("Initiating direct URL NFC lease pull to remote storage...")
    deployed_vm = self._execute_lease_pull(
        ovf_descriptor=ovf_xml,
        resource_pool=res_pool,
        vm_folder=vm_folder,
        datastore=datastore,
        network=network,
        ova_url=vcf_installer_ova_url,
        ssl_thumbprint=ssl_thumbprint,
        vcf_vm_name=vcf_vm_name,
    )

    logger.info(
        "Successfully deployed VM '%s' via streaming direct-URL NFC pull.",
        vcf_vm_name,
    )
    return deployed_vm

  def _resolve_host_resources(
      self, port_group_name: str
  ) -> Tuple[Any, Any, Any, Any]:
    """Resolves root pool, root VM folder, vSAN datastore, and port group network."""
    host = self.esxi.get_host_system()
    res_pool, vm_folder = self.esxi.get_resource_pool_and_folder()

    datastore = None
    for ds in getattr(host, "datastore", []) or []:
      if (
          getattr(ds, "name", "")
          == constants.VMDeployerDefaults.DEFAULT_DATASTORE_NAME
      ):
        datastore = ds
        break
    if not datastore and getattr(host, "datastore", None):
      datastore = host.datastore[0]

    if not datastore:
      raise models.ValidationError(
          f"vsanDatastore not located on ESXi host {self.esxi.host_ip}."
      )

    network = None
    for net in getattr(host, "network", []) or []:
      if getattr(net, "name", "") == port_group_name:
        network = net
        break

    if not network:
      raise models.ValidationError(
          f"Port group '{port_group_name}' not found in ESXi host network"
          " inventory."
      )

    return res_pool, vm_folder, datastore, network

  def _check_vm_exists(self, vcf_vm_name: str) -> Optional[Any]:
    """Queries container view for VirtualMachine instances matching vcf_vm_name."""
    si = self.esxi.connect_pyvmomi()
    content = si.RetrieveContent()
    if not vim:
      return None
    container = content.viewManager.CreateContainerView(
        content.rootFolder, [vim.VirtualMachine], True
    )
    try:
      for vm_ref in container.view:
        if getattr(vm_ref, "name", "") == vcf_vm_name:
          return vm_ref
      return None
    finally:
      container.Destroy()

  _cached_system_ca_certs: Optional[List[x509.Certificate]] = None

  @staticmethod
  def _compute_bytes_digests(payload: bytes) -> Dict[str, str]:
    """Computes SHA1, SHA256, SHA384, and SHA512 hex digests for a byte buffer."""
    return {
        "SHA1": hashlib.sha1(payload).hexdigest().lower(),
        "SHA256": hashlib.sha256(payload).hexdigest().lower(),
        "SHA384": hashlib.sha384(payload).hexdigest().lower(),
        "SHA512": hashlib.sha512(payload).hexdigest().lower(),
    }

  @staticmethod
  def _compute_stream_digests(
      file_obj: Any,
      chunk_size: int = 1024 * 1024,
      algorithms: Optional[Tuple[str, ...]] = None,
  ) -> Dict[str, str]:
    """Computes hex digests over a stream for the requested hash algorithms."""
    algo_factories = {
        "SHA1": hashlib.sha1,
        "SHA256": hashlib.sha256,
        "SHA384": hashlib.sha384,
        "SHA512": hashlib.sha512,
    }
    selected_algos = (
        tuple(a.upper() for a in algorithms if a.upper() in algo_factories)
        if algorithms
        else tuple(algo_factories.keys())
    )
    hashers = {alg: algo_factories[alg]() for alg in selected_algos}
    while True:
      chunk = file_obj.read(chunk_size)
      if not chunk:
        break
      for h in hashers.values():
        h.update(chunk)
    return {alg: h.hexdigest().lower() for alg, h in hashers.items()}

  @staticmethod
  def _parse_ova_manifest_entries(mf_text: str) -> Dict[str, Tuple[str, str]]:
    """Parses OVA .mf manifest entries into basename -> (algorithm, hex_digest)."""
    manifest_entries: Dict[str, Tuple[str, str]] = {}
    for raw_line in mf_text.splitlines():
      line = raw_line.strip()
      if not line:
        continue
      match = re.match(
          constants.ValidationRules.OVA_MANIFEST_ENTRY_PATTERN,
          line,
          flags=re.IGNORECASE,
      )
      if not match:
        raise models.NonRetryableError(
            f"Malformed manifest entry in OVA .mf file: '{line}'"
        )
      algo = match.group(1).upper()
      fname = os.path.basename(match.group(2).strip())
      expected_digest = match.group(3).strip().lower()
      manifest_entries[fname] = (algo, expected_digest)
    return manifest_entries

  def _verify_ova_manifest(
      self,
      mf_text: str,
      ovf_name: str,
      member_hashes: Dict[str, Dict[str, str]],
  ) -> None:
    """Verifies OVA member digests against the .mf manifest file.

    Args:
        mf_text: Decoded text contents of the .mf manifest file.
        ovf_name: Basename of the extracted .ovf descriptor file.
        member_hashes: Mapping of member basenames to algorithm->hexdigest maps.

    Raises:
        models.NonRetryableError: If the manifest is empty, malformed, missing
          the .ovf entry, missing any listed archive member, contains unlisted
          archive members, or any computed member digest does not match.
    """
    manifest_entries = self._parse_ova_manifest_entries(mf_text)

    if not manifest_entries:
      raise models.NonRetryableError(
          "OVA manifest (.mf) file contains no digest entries."
      )

    if ovf_name not in manifest_entries:
      raise models.NonRetryableError(
          f"OVF descriptor '{ovf_name}' is missing from OVA manifest (.mf)."
      )

    for fname, (algo, expected_hex) in manifest_entries.items():
      if fname not in member_hashes:
        raise models.NonRetryableError(
            f"OVA archive is missing file '{fname}' listed in manifest (.mf)."
        )
      actual_hex = member_hashes[fname].get(algo, "").lower()
      if actual_hex != expected_hex:
        raise models.NonRetryableError(
            f"OVA manifest (.mf) {algo} hash mismatch for '{fname}':"
            f" expected {expected_hex}, got {actual_hex}."
        )

    for fname in member_hashes:
      if fname not in manifest_entries:
        raise models.NonRetryableError(
            f"OVA archive contains file '{fname}' not listed in manifest (.mf)."
        )

  @classmethod
  def _load_trusted_ca_certs(
      cls, trusted_ca_pem: Optional[str] = None
  ) -> List[x509.Certificate]:
    """Loads trusted Root CA certificates from PEM string, env var, or system store."""
    if trusted_ca_pem is not None:
      pem_blocks = re.findall(
          constants.ValidationRules.PEM_CERTIFICATE_PATTERN,
          trusted_ca_pem,
          flags=re.DOTALL,
      )
      return [
          x509.load_pem_x509_certificate(b.encode("utf-8")) for b in pem_blocks
      ]

    env_ca_path = os.environ.get(
        constants.ValidationRules.OVA_SIGNING_CA_BUNDLE_ENV_VAR
    )
    if env_ca_path and os.path.isfile(env_ca_path):
      with open(env_ca_path, "r", encoding="utf-8", errors="replace") as f:
        pem_text = f.read()
      pem_blocks = re.findall(
          constants.ValidationRules.PEM_CERTIFICATE_PATTERN,
          pem_text,
          flags=re.DOTALL,
      )
      return [
          x509.load_pem_x509_certificate(b.encode("utf-8")) for b in pem_blocks
      ]

    if cls._cached_system_ca_certs is not None:
      return cls._cached_system_ca_certs

    ca_file = os.environ.get("SSL_CERT_FILE") or getattr(
        ssl.get_default_verify_paths(), "cafile", None
    )
    loaded: List[x509.Certificate] = []
    if ca_file and os.path.isfile(ca_file):
      with open(ca_file, "r", encoding="utf-8", errors="replace") as f:
        pem_text = f.read()
      for block in re.findall(
          constants.ValidationRules.PEM_CERTIFICATE_PATTERN,
          pem_text,
          flags=re.DOTALL,
      ):
        try:
          loaded.append(x509.load_pem_x509_certificate(block.encode("utf-8")))
        except Exception:  # pylint: disable=broad-exception-caught
          continue
    cls._cached_system_ca_certs = loaded
    return loaded

  @staticmethod
  def _validate_cert_validity_window(
      cert: x509.Certificate, now: datetime.datetime
  ) -> None:
    """Verifies that an X.509 certificate's validity window includes 'now'."""
    not_before = getattr(cert, "not_valid_before_utc", None)
    if not_before is None:
      not_before = cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
    not_after = getattr(cert, "not_valid_after_utc", None)
    if not_after is None:
      not_after = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)

    if now < not_before or now > not_after:
      raise models.NonRetryableError(
          "OVA signing certificate in .cert is expired or not yet valid"
          f" (valid from {not_before.isoformat()} to {not_after.isoformat()})."
      )

  @classmethod
  def _verify_x509_chain(
      cls,
      cert_chain: List[x509.Certificate],
      trusted_roots: List[x509.Certificate],
      now: datetime.datetime,
  ) -> None:
    """Verifies the X.509 issuer chain from leaf certificate up to a trusted Root CA."""
    if not trusted_roots:
      raise models.NonRetryableError(
          "No trusted Root CA certificates available to verify OVA .cert chain."
      )

    roots_by_subject: Dict[x509.Name, List[x509.Certificate]] = {}
    for root in trusted_roots:
      roots_by_subject.setdefault(root.subject, []).append(root)

    intermediates = cert_chain[1:]
    current = cert_chain[0]
    visited = {current}
    intermediate_count = 0

    for _ in range(len(cert_chain) + 1):
      for root_ca in roots_by_subject.get(current.issuer, []):
        try:
          cls._validate_cert_validity_window(root_ca, now)
          bc_ext = root_ca.extensions.get_extension_for_class(
              x509.BasicConstraints
          )
          if not bc_ext.value.ca:
            continue
          if (
              bc_ext.value.path_length is not None
              and intermediate_count > bc_ext.value.path_length
          ):
            continue
          try:
            ku_ext = root_ca.extensions.get_extension_for_class(x509.KeyUsage)
            if not ku_ext.value.key_cert_sign:
              continue
          except x509.ExtensionNotFound:
            pass
          current.verify_directly_issued_by(root_ca)
          return
        except Exception:  # pylint: disable=broad-exception-caught
          continue

      next_issuer: Optional[x509.Certificate] = None
      for candidate in intermediates:
        if candidate in visited or candidate.subject != current.issuer:
          continue
        try:
          cls._validate_cert_validity_window(candidate, now)
          bc_ext = candidate.extensions.get_extension_for_class(
              x509.BasicConstraints
          )
          if not bc_ext.value.ca:
            continue
          if (
              bc_ext.value.path_length is not None
              and intermediate_count > bc_ext.value.path_length
          ):
            continue
          try:
            ku_ext = candidate.extensions.get_extension_for_class(x509.KeyUsage)
            if not ku_ext.value.key_cert_sign:
              continue
          except x509.ExtensionNotFound:
            pass
          current.verify_directly_issued_by(candidate)
          next_issuer = candidate
          break
        except Exception:  # pylint: disable=broad-exception-caught
          continue

      if next_issuer is None:
        break
      visited.add(next_issuer)
      current = next_issuer
      intermediate_count += 1

    raise models.NonRetryableError(
        "OVA signing certificate chain is untrusted: unable to verify issuer"
        " chain against trusted Root CAs."
    )

  def _verify_ova_certificate(
      self,
      cert_text: str,
      mf_name: str,
      mf_bytes: bytes,
      trusted_ca_pem: Optional[str] = None,
  ) -> None:
    """Verifies the X.509 certificate chain, key usage, and cryptographic signature in .cert over .mf.

    Args:
        cert_text: Decoded text contents of the .cert signature file.
        mf_name: Basename of the .mf manifest file.
        mf_bytes: Raw bytes of the .mf manifest file as signed in the archive.
        trusted_ca_pem: Optional PEM bundle of trusted Root CAs (overrides
          default CA store when provided).

    Raises:
        models.NonRetryableError: If the certificate is missing, malformed,
          expired, untrusted, missing codeSigning EKU, or signature verification
          over .mf fails.
    """
    sig_algo: Optional[str] = None
    signed_target: Optional[str] = None
    sig_hex: Optional[str] = None

    for raw_line in cert_text.splitlines():
      line = raw_line.strip()
      if not line:
        continue
      if line.startswith("-----BEGIN"):
        break
      match = re.match(
          constants.ValidationRules.OVA_MANIFEST_ENTRY_PATTERN,
          line,
          flags=re.IGNORECASE,
      )
      if match:
        sig_algo = match.group(1).upper()
        signed_target = os.path.basename(match.group(2).strip())
        sig_hex = match.group(3).strip()
        break

    if not sig_algo or not signed_target or not sig_hex:
      raise models.NonRetryableError(
          "Missing or malformed signature header in OVA .cert file."
      )

    if mf_name and signed_target != os.path.basename(mf_name):
      raise models.NonRetryableError(
          f"OVA .cert signature targets '{signed_target}', expected manifest"
          f" '{os.path.basename(mf_name)}'."
      )

    try:
      signature_bytes = bytes.fromhex(sig_hex)
    except ValueError as exc:
      raise models.NonRetryableError(
          f"Invalid hexadecimal signature in OVA .cert file: {exc}"
      ) from exc

    hash_alg_map = {
        "SHA256": hashes.SHA256(),
        "SHA384": hashes.SHA384(),
        "SHA512": hashes.SHA512(),
    }
    hash_alg = hash_alg_map.get(sig_algo)
    if not hash_alg:
      raise models.NonRetryableError(
          "Unsupported or weak signature digest algorithm in OVA .cert:"
          f" '{sig_algo}'"
      )

    pem_blocks = re.findall(
        constants.ValidationRules.PEM_CERTIFICATE_PATTERN,
        cert_text,
        flags=re.DOTALL,
    )
    if not pem_blocks:
      raise models.NonRetryableError(
          "No PEM-encoded X.509 certificate found in OVA .cert file."
      )

    try:
      cert_chain = [
          x509.load_pem_x509_certificate(block.encode("utf-8"))
          for block in pem_blocks
      ]
    except Exception as exc:
      raise models.NonRetryableError(
          f"Failed to parse X.509 certificate in OVA .cert file: {exc}"
      ) from exc

    now = datetime.datetime.now(datetime.timezone.utc)
    for cert_item in cert_chain:
      self._validate_cert_validity_window(cert_item, now)

    leaf_cert = cert_chain[0]
    try:
      bc_ext = leaf_cert.extensions.get_extension_for_class(
          x509.BasicConstraints
      )
      if bc_ext.value.ca:
        raise models.NonRetryableError(
            "OVA leaf signing certificate must not be a CA certificate."
        )
    except x509.ExtensionNotFound:
      pass

    try:
      ku_ext = leaf_cert.extensions.get_extension_for_class(x509.KeyUsage)
      if not ku_ext.value.digital_signature:
        raise models.NonRetryableError(
            "OVA signing certificate KeyUsage does not permit digitalSignature."
        )
    except x509.ExtensionNotFound:
      pass

    try:
      eku_ext = leaf_cert.extensions.get_extension_for_class(
          x509.ExtendedKeyUsage
      )
      if ExtendedKeyUsageOID.CODE_SIGNING not in eku_ext.value:
        raise models.NonRetryableError(
            "OVA signing certificate ExtendedKeyUsage does not permit"
            " codeSigning."
        )
    except x509.ExtensionNotFound as exc:
      raise models.NonRetryableError(
          "OVA signing certificate is missing required ExtendedKeyUsage"
          " (codeSigning) extension."
      ) from exc

    trusted_roots = self._load_trusted_ca_certs(trusted_ca_pem)
    self._verify_x509_chain(cert_chain, trusted_roots, now)

    pub_key = leaf_cert.public_key()
    try:
      if isinstance(pub_key, rsa.RSAPublicKey):
        pub_key.verify(
            signature_bytes, mf_bytes, padding.PKCS1v15(), hash_alg
        )
      elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        pub_key.verify(signature_bytes, mf_bytes, ec.ECDSA(hash_alg))
      else:
        raise models.NonRetryableError(
            "Unsupported public key algorithm in OVA .cert:"
            f" {type(pub_key).__name__}"
        )
    except models.NonRetryableError:
      raise
    except Exception as exc:
      raise models.NonRetryableError(
          "OVA cryptographic signature verification failed for manifest"
          f" '{mf_name}': {exc}"
      ) from exc

  def _verify_ova_integrity(
      self,
      ova_url: str,
      ovf_name: str,
      member_hashes: Dict[str, Dict[str, str]],
      mf_name: Optional[str],
      mf_bytes: Optional[bytes],
      cert_name: Optional[str],
      cert_bytes: Optional[bytes],
      require_signature: bool = False,
      verified_whole_ova_sha256: bool = False,
      allow_unverified_ova: bool = False,
      trusted_ca_pem: Optional[str] = None,
  ) -> None:
    """Orchestrates .mf manifest and .cert signature verification for an OVA."""
    if require_signature and (mf_bytes is None or cert_bytes is None):
      raise models.NonRetryableError(
          f"OVA signature verification required for '{ova_url}', but .mf"
          " manifest or .cert certificate is missing in archive."
      )

    if cert_bytes is not None and mf_bytes is None:
      raise models.NonRetryableError(
          f"OVA archive at '{ova_url}' contains a .cert file ('{cert_name}')"
          " without a corresponding .mf manifest."
      )

    if mf_bytes is not None:
      self._verify_ova_manifest(
          mf_text=mf_bytes.decode("utf-8", errors="replace"),
          ovf_name=ovf_name,
          member_hashes=member_hashes,
      )
      logger.info(
          "Successfully verified OVA manifest (.mf) integrity for '%s'.",
          mf_name,
      )

    verified_cert_signature = False
    if cert_bytes is not None and mf_bytes is not None:
      self._verify_ova_certificate(
          cert_text=cert_bytes.decode("utf-8", errors="replace"),
          mf_name=mf_name or "",
          mf_bytes=mf_bytes,
          trusted_ca_pem=trusted_ca_pem,
      )
      verified_cert_signature = True
      logger.info(
          "Successfully verified OVA X.509 certificate and signature (.cert)"
          " for '%s'.",
          cert_name,
      )

    if not verified_whole_ova_sha256 and not verified_cert_signature:
      if not allow_unverified_ova:
        raise models.NonRetryableError(
            f"OVA integrity/authenticity verification failed for '{ova_url}':"
            " neither a verified depot SHA-256 digest nor a trusted X.509"
            " .cert signature is present."
        )
      logger.warning(
          "Proceeding with unverified OVA archive at '%s' because"
          " allow_unverified_ova=True.",
          ova_url,
      )

  def _fetch_and_parse_ovf_descriptor(
      self,
      ova_url: str,
      expected_ova_sha256: Optional[str] = None,
      require_signature: bool = False,
      ssl_thumbprint: Optional[str] = None,
      allow_unverified_ova: bool = False,
      trusted_ca_pem: Optional[str] = None,
  ) -> str:
    """Opens streaming HTTP connection to parse TAR headers, verify OVA integrity, and extract OVF XML."""
    clean_expected_sha256: Optional[str] = None
    if expected_ova_sha256 is not None:
      clean_expected_sha256 = expected_ova_sha256.strip().lower()
      if not re.match(
          constants.ValidationRules.SHA256_HEX_PATTERN, clean_expected_sha256
      ):
        raise models.ValidationError(
            "Invalid expected_ova_sha256"
            f" '{expected_ova_sha256}': must be a valid 64-character"
            " hexadecimal SHA-256 digest."
        )

    ovf_xml: Optional[str] = None
    ovf_name: Optional[str] = None
    mf_bytes: Optional[bytes] = None
    mf_name: Optional[str] = None
    cert_bytes: Optional[bytes] = None
    cert_name: Optional[str] = None
    member_hashes: Dict[str, Dict[str, str]] = {}
    parsed_mf_entries: Optional[Dict[str, Tuple[str, str]]] = None
    verified_whole_ova_sha256 = False

    try:
      parsed = urllib.parse.urlparse(ova_url)
      headers = {"User-Agent": constants.VMDeployerDefaults.HTTP_USER_AGENT}
      req = urllib.request.Request(ova_url, headers=headers)
      ssl_ctx = network_utils.create_depot_ssl_context(
          fqdn_host=parsed.hostname,
          expected_thumbprint=ssl_thumbprint,
      )
      with urllib.request.urlopen(
          req,
          context=ssl_ctx,
          timeout=constants.NetworkingDefaults.HTTP_TIMEOUT_SECONDS,
      ) as resp:
        if resp.status != 200:
          raise models.NonRetryableError(
              f"HTTP fetch failed for OVF descriptor from '{ova_url}': status"
              f" {resp.status}"
          )
        stream: Any = (
            _HashingStreamWrapper(resp) if clean_expected_sha256 else resp
        )
        with tarfile.open(fileobj=stream, mode="r|*") as tar:
          for member in tar:
            if not member.isfile():
              continue
            member_basename = os.path.basename(member.name)
            lower_name = member_basename.lower()

            if lower_name.endswith(".ovf"):
              ovf_file = tar.extractfile(member)
              if ovf_file:
                ovf_bytes = ovf_file.read()
                ovf_name = member_basename
                member_hashes[member_basename] = self._compute_bytes_digests(
                    ovf_bytes
                )
                ovf_xml = ovf_bytes.decode("utf-8", errors="replace")
            elif lower_name.endswith(".mf"):
              mf_file = tar.extractfile(member)
              if mf_file:
                mf_bytes = mf_file.read()
                mf_name = member_basename
                parsed_mf_entries = self._parse_ova_manifest_entries(
                    mf_bytes.decode("utf-8", errors="replace")
                )
            elif lower_name.endswith(".cert"):
              cert_file = tar.extractfile(member)
              if cert_file:
                cert_bytes = cert_file.read()
                cert_name = member_basename
            else:
              if (
                  not allow_unverified_ova
                  or clean_expected_sha256
                  or mf_bytes is not None
                  or require_signature
              ):
                other_file = tar.extractfile(member)
                if other_file:
                  req_algos: Optional[Tuple[str, ...]] = None
                  if parsed_mf_entries and member_basename in parsed_mf_entries:
                    req_algos = (parsed_mf_entries[member_basename][0],)
                  member_hashes[member_basename] = self._compute_stream_digests(
                      other_file, algorithms=req_algos
                  )
              elif ovf_xml is not None and lower_name.endswith(".vmdk"):
                break

        if clean_expected_sha256 and isinstance(stream, _HashingStreamWrapper):
          actual_sha256 = stream.drain().lower()
          if actual_sha256 != clean_expected_sha256:
            raise models.NonRetryableError(
                f"OVA SHA-256 integrity check failed for '{ova_url}': expected"
                f" {clean_expected_sha256}, got {actual_sha256}."
            )
          verified_whole_ova_sha256 = True
          logger.info(
              "Verified whole-OVA SHA-256 digest for '%s': %s",
              ova_url,
              actual_sha256,
          )
    except Exception as exc:  # pylint: disable=broad-exception-caught
      if isinstance(exc, (models.ValidationError, models.NonRetryableError)):
        raise exc
      raise models.RetryableError(
          f"Failed to stream and parse .ovf descriptor from '{ova_url}': {exc}"
      ) from exc

    if ovf_xml is None or ovf_name is None:
      raise models.NonRetryableError(
          f"No .ovf descriptor file located in OVA archive at '{ova_url}'."
      )

    self._verify_ova_integrity(
        ova_url=ova_url,
        ovf_name=ovf_name,
        member_hashes=member_hashes,
        mf_name=mf_name,
        mf_bytes=mf_bytes,
        cert_name=cert_name,
        cert_bytes=cert_bytes,
        require_signature=require_signature,
        verified_whole_ova_sha256=verified_whole_ova_sha256,
        allow_unverified_ova=allow_unverified_ova,
        trusted_ca_pem=trusted_ca_pem,
    )
    return ovf_xml

  def _execute_lease_pull(
      self,
      ovf_descriptor: str,
      resource_pool: Any,
      vm_folder: Any,
      datastore: Any,
      network: Any,
      ova_url: str,
      ssl_thumbprint: Optional[str],
      vcf_vm_name: str,
  ) -> Any:
    """Creates vApp import spec, starts NFC lease, and invokes HttpNfcLeasePull."""
    if not vim:
      raise models.NonRetryableError("pyVmomi package is not installed.")

    si = self.esxi.connect_pyvmomi()
    ovf_mgr = si.RetrieveContent().ovfManager

    # Dynamically inspect OVF descriptor to extract logical network names from <NetworkSection>
    pdp = vim.OvfManager.ParseDescriptorParams()
    desc_result = ovf_mgr.ParseDescriptor(ovf_descriptor, pdp)
    if getattr(desc_result, "error", None):
      logger.warning(
          "ParseDescriptor encountered warnings/errors inspecting OVF"
          " descriptor: %s",
          desc_result.error,
      )

    raw_networks = getattr(desc_result, "network", None)
    if not raw_networks or not isinstance(raw_networks, (list, tuple)):
      error_msg = (
          f"No logical networks found in OVF descriptor for VM '{vcf_vm_name}'."
      )
      if getattr(desc_result, "error", None):
        error_msg += f" Parse errors: {desc_result.error}"
      raise models.NonRetryableError(error_msg)

    logical_networks: List[str] = [
        item.name
        for item in raw_networks
        if hasattr(item, "name") and item.name
    ]

    logger.info(
        "Configuring OVF network mapping for %d logical network(s): %s",
        len(logical_networks),
        logical_networks,
    )
    network_mappings = []
    for net_name in logical_networks:
      net_map = vim.OvfManager.NetworkMapping()
      net_map.name = net_name
      net_map.network = network
      network_mappings.append(net_map)

    params = vim.OvfManager.CreateImportSpecParams()
    params.entityName = vcf_vm_name
    params.diskProvisioning = (
        constants.VMDeployerDefaults.DISK_PROVISIONING_THIN
    )
    params.networkMapping = network_mappings

    import_spec = ovf_mgr.CreateImportSpec(
        ovf_descriptor, resource_pool, datastore, params
    )
    if getattr(import_spec, "error", None):
      raise models.NonRetryableError(
          f"Failed to create import spec for VM '{vcf_vm_name}':"
          f" {import_spec.error}"
      )

    lease = resource_pool.ImportVApp(
        spec=import_spec.importSpec, folder=vm_folder
    )

    # Wait for lease to become ready
    self._wait_for_nfc_lease_ready(lease)

    # Prepare file pull specifications
    file_items = getattr(import_spec, "fileItem", []) or []
    updated_files = []
    for item in file_items:
      src_file = vim.HttpNfcLease.SourceFile()
      src_file.targetDeviceId = item.deviceId
      src_file.url = ova_url
      src_file.sslThumbprint = ssl_thumbprint or ""
      src_file.memberName = item.path
      src_file.create = False
      updated_files.append(src_file)

    try:
      task = lease.HttpNfcLeasePullFromUrls_Task(files=updated_files)
      self._wait_for_task(task)
      # Capture VM entity reference before completing/destroying the lease
      vm_entity = getattr(getattr(lease, "info", None), "entity", None)
      lease.HttpNfcLeaseComplete()
    except Exception as exc:  # pylint: disable=broad-exception-caught
      try:
        lease.HttpNfcLeaseAbort()
      except Exception:  # pylint: disable=broad-exception-caught
        pass
      raise models.DeployerError(
          f"NFC lease pull task failed for VM '{vcf_vm_name}': {exc}"
      ) from exc

    if not vm_entity:
      vm_entity = self._check_vm_exists(vcf_vm_name)

    if not vm_entity:
      raise models.DeployerError(
          "Failed to resolve created VirtualMachine reference for"
          f" '{vcf_vm_name}'."
      )

    return vm_entity

  def _wait_for_nfc_lease_ready(
      self,
      lease: Any,
      timeout_seconds: int = (
          constants.VMDeployerDefaults.NFC_LEASE_TIMEOUT_SECONDS
      ),
  ) -> None:
    """Polls NFC lease state until ready or error."""
    start_time = time.time()
    while time.time() - start_time < timeout_seconds:
      state = getattr(lease, "state", None)
      if vim and state == vim.HttpNfcLease.State.ready:
        return
      if vim and state == vim.HttpNfcLease.State.error:
        err_msg = getattr(
            getattr(lease, "error", None), "localizedMessage", "Lease Error"
        )
        raise models.DeployerError(f"NFC lease failed: {err_msg}")
      time.sleep(
          constants.VMDeployerDefaults.NFC_LEASE_POLL_INTERVAL_SECONDS
      )
    raise models.RetryableError(
        "Timed out waiting for NFC lease to reach ready state."
    )

  def _wait_for_task(
      self,
      task: Any,
      timeout_seconds: int = constants.VMDeployerDefaults.TASK_TIMEOUT_SECONDS,
  ) -> None:
    """Polls pyVmomi Task object until completion."""
    start_time = time.time()
    while time.time() - start_time < timeout_seconds:
      info = getattr(task, "info", None)
      if info:
        if info.state == "success":
          return
        if info.state == "error":
          err_obj = getattr(info, "error", None)
          err_msg = (
              getattr(err_obj, "localizedMessage", None)
              or getattr(err_obj, "msg", None)
              or str(err_obj)
              or "Task Failed"
          )
          logger.error(
              "Task error details: %s (error object: %r)", err_msg, err_obj
          )
          raise models.DeployerError(f"Task failed: {err_msg}")
      time.sleep(constants.VMDeployerDefaults.TASK_POLL_INTERVAL_SECONDS)
    raise models.RetryableError("Timed out waiting for task completion.")

  # ============================================================================
  # Phase 3d: OVF Environment Configuration
  # ============================================================================

  def configure_ovf_environment(
      self,
      vm_reference: Any,
      sddc_manager_ip: str,
      gateway: str,
      netmask: str,
      root_pwd: str,
      local_pwd: str,
      fqdn: str,
      domain: str,
      searchpath: str,
      dns_server: Optional[str] = None,
  ) -> None:
    """Executes Phase 3d OVF environment configuration injection for deployed VM."""
    logger.info(
        "Phase 3d: Configuring OVF properties for appliance '%s' (%s)...",
        fqdn,
        sddc_manager_ip,
    )
    self.esxi.connect_pyvmomi()

    effective_dns_server = (
        dns_server
        if dns_server
        else constants.NetworkingDefaults.DEFAULT_METADATA_SERVER
    )

    clean_domain = domain.rstrip(".") if domain else domain
    effective_ntp_server = (
        f"ntp.{clean_domain}"
        if clean_domain
        else constants.NetworkingDefaults.DEFAULT_METADATA_SERVER
    )

    xml_payload = self._marshal_ovf_properties(
        sddc_manager_ip=sddc_manager_ip,
        gateway=gateway,
        netmask=netmask,
        root_pwd=root_pwd,
        local_pwd=local_pwd,
        fqdn=fqdn,
        domain=domain,
        searchpath=searchpath,
        ntp_server=effective_ntp_server,
        dns_server=effective_dns_server,
    )

    self._inject_guestinfo(vm_reference, xml_payload)
    logger.info("Successfully configured and injected OVF environment into VM.")

  def _marshal_ovf_properties(
      self,
      sddc_manager_ip: str,
      gateway: str,
      netmask: str,
      root_pwd: str,
      local_pwd: str,
      fqdn: str,
      domain: str,
      searchpath: str,
      ntp_server: Optional[str] = None,
      dns_server: str = constants.NetworkingDefaults.DEFAULT_METADATA_SERVER,
  ) -> str:
    """Constructs OVF environment XML string with network and auth properties."""
    clean_domain = domain.rstrip(".") if domain else domain
    effective_ntp_server = (
        ntp_server
        if ntp_server
        else (
            f"ntp.{clean_domain}"
            if clean_domain
            else constants.NetworkingDefaults.DEFAULT_METADATA_SERVER
        )
    )
    env_props = [
        (constants.OVFPropertyKeys.ROOT_PASSWORD, root_pwd),
        (constants.OVFPropertyKeys.LOCAL_USER_PASSWORD, local_pwd),
        (constants.OVFPropertyKeys.VAMI_HOSTNAME, fqdn),
        (constants.OVFPropertyKeys.GUESTINFO_NTP, effective_ntp_server),
        (constants.OVFPropertyKeys.VAMI_IP0_SDDC_MANAGER, sddc_manager_ip),
        (constants.OVFPropertyKeys.VAMI_NETMASK0_SDDC_MANAGER, netmask),
        (constants.OVFPropertyKeys.VAMI_GATEWAY_SDDC_MANAGER, gateway),
        (constants.OVFPropertyKeys.VAMI_DOMAIN_SDDC_MANAGER, domain),
        (constants.OVFPropertyKeys.VAMI_SEARCHPATH_SDDC_MANAGER, searchpath),
        (constants.OVFPropertyKeys.VAMI_DNS_SDDC_MANAGER, dns_server),
    ]
    props_xml = "".join(
        f'<Property oe:key="{key}" oe:value="{val}"/>' for key, val in env_props
    )
    xml_str = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Environment xmlns="http://schemas.dmtf.org/ovf/environment/1"'
        ' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
        ' xmlns:oe="http://schemas.dmtf.org/ovf/environment/1"'
        ' xmlns:ve="http://www.vmware.com/schema/ovfenv"'
        f' oe:id="" ve:esxId="{fqdn}">'
        f"<PropertySection>{props_xml}</PropertySection>"
        "</Environment>"
    )
    return xml_str

  def _inject_guestinfo(self, vm_reference: Any, xml_payload: str) -> None:
    """Appends 'guestinfo.ovfEnv' and 'guestinfo.ovfEnv/len' via ReconfigVM_Task."""
    if not vim:
      raise models.NonRetryableError("pyVmomi package is not installed.")

    payload_len = str(len(xml_payload.encode("utf-8")))
    logger.debug(
        "Injecting guestinfo.ovfEnv (length: %s bytes) via ReconfigVM_Task...",
        payload_len,
    )

    opt_env = vim.option.OptionValue()
    opt_env.key = constants.VMDeployerDefaults.GUESTINFO_OVF_ENV
    opt_env.value = xml_payload

    opt_len = vim.option.OptionValue()
    opt_len.key = constants.VMDeployerDefaults.GUESTINFO_OVF_ENV_LEN
    opt_len.value = payload_len

    spec = vim.vm.ConfigSpec()
    spec.extraConfig = [opt_env, opt_len]

    task = vm_reference.ReconfigVM_Task(spec=spec)
    self._wait_for_task(task)

  # ============================================================================
  # Phase 3e: VM Power On & IP Acquisition Monitoring
  # ============================================================================

  def power_on_and_wait_for_ip(
      self,
      vm_reference: Any,
      target_ip: str,
      poll_interval_seconds: int = (
          constants.DeployerDefaults.POWER_ON_POLL_INTERVAL_SECONDS
      ),
      timeout_seconds: int = (
          constants.DeployerDefaults.POWER_ON_TIMEOUT_SECONDS
      ),
  ) -> None:
    """Executes Phase 3e VM power-on initialization and IP address readiness check."""
    logger.info(
        "Phase 3e: Initiating power management and IP check for %s...",
        target_ip,
    )
    self.esxi.connect_pyvmomi()

    self._power_on_vm(vm_reference)
    self._poll_for_guest_ip(
        vm_reference=vm_reference,
        target_ip=target_ip,
        poll_interval_seconds=poll_interval_seconds,
        timeout_seconds=timeout_seconds,
    )
    logger.info(
        "VM successfully initialized and verified accessible at IP %s.",
        target_ip,
    )

  def _power_on_vm(self, vm_reference: Any) -> None:
    """Inspects runtime power state and invokes PowerOnVM_Task if VM is off."""
    state = getattr(getattr(vm_reference, "runtime", None), "powerState", None)
    if vim and state == vim.VirtualMachinePowerState.poweredOn:
      logger.info("VM is already powered on.")
      return

    logger.info("Powering on VM via PowerOnVM_Task...")
    task = vm_reference.PowerOnVM_Task()
    self._wait_for_task(task)

  def _poll_for_guest_ip(
      self,
      vm_reference: Any,
      target_ip: str,
      poll_interval_seconds: int,
      timeout_seconds: int,
  ) -> None:
    """Loops monitoring guest networking telemetry until matching IP appears."""
    logger.info(
        "Polling VMware tools telemetry for IPv4 '%s' (Max timeout: %d s)...",
        target_ip,
        timeout_seconds,
    )
    start_time = time.time()
    while time.time() - start_time < timeout_seconds:
      guest = getattr(vm_reference, "guest", None)
      if guest:
        ip_addr = getattr(guest, "ipAddress", None)
        if ip_addr:
          logger.info("Guest tools reported IP address: %s", ip_addr)
          if not target_ip or ip_addr == target_ip:
            return
        # Inspect guest interfaces array
        for net_if in getattr(guest, "net", []) or []:
          for ip_obj in getattr(net_if, "ipAddress", []) or []:
            if ip_obj == target_ip:
              logger.info("Target IP %s matched on guest interface.", target_ip)
              return
      time.sleep(poll_interval_seconds)

    raise models.RetryableError(
        f"Timed out after {timeout_seconds}s waiting for guest to acquire IP"
        f" '{target_ip}'."
    )

  def bypass_vcf_hcl_disk_validation(
      self,
      vcf_ip: str,
      root_pwd: str,
      local_pwd: Optional[str] = None,
      appliance_user: str = "vcf",
      timeout_seconds: int = 180,
      poll_interval_seconds: int = 5,
  ) -> None:
    """Logs in as appliance user, switches to root via 'su -', and applies HCL bypass."""
    login_user = appliance_user if local_pwd else "root"
    login_pwd = local_pwd if local_pwd else root_pwd
    logger.info(
        "Phase 3f: Connecting to VCF appliance at %s as '%s'...",
        vcf_ip,
        login_user,
    )
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # 1. Wait for SSH daemon
    start_time = time.time()
    connected = False
    while time.time() - start_time < timeout_seconds:
      try:
        client.connect(
            hostname=vcf_ip,
            username=login_user,
            password=login_pwd,
            timeout=10,
            allow_agent=False,
            look_for_keys=False,
        )
        connected = True
        logger.info(
            "SSH connection established to VCF appliance %s as '%s'.",
            vcf_ip,
            login_user,
        )
        break
      except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.debug("Waiting for VCF SSH daemon (%s)...", exc)
        time.sleep(poll_interval_seconds)
    if not connected:
      raise models.DeployerError(
          f"Timed out after {timeout_seconds}s waiting for SSH on VCF"
          f" appliance {vcf_ip}."
      )
    shell = None
    try:
      # 2. Open interactive shell session
      shell = client.invoke_shell()
      shell.settimeout(15.0)
      def _read_until(
          expected_patterns: list[str], timeout: int = 15
      ) -> tuple[bool, str]:
        accumulated = ""
        read_start = time.time()
        while time.time() - read_start < timeout:
          if shell.recv_ready():
            chunk = shell.recv(4096).decode("utf-8", errors="replace")
            accumulated += chunk
            for pattern in expected_patterns:
              if pattern.lower() in accumulated.lower():
                return True, accumulated
          time.sleep(0.1)
        return False, accumulated
      # Drain initial welcome banner/prompt
      time.sleep(1.0)
      if shell.recv_ready():
        shell.recv(4096)
      # 3. Switch to root via 'su -'
      if login_user != "root":
        logger.info("Elevating to root via 'su -' on %s...", vcf_ip)
        shell.send("su -\n")
        matched, out = _read_until(["Password:"], timeout=10)
        if not matched:
          raise models.DeployerError(
              f"Timed out waiting for root Password prompt on {vcf_ip}:"
              f" {out.strip()}"
          )
        # Send root password
        shell.send(root_pwd + "\n")
        time.sleep(1.0)
        # Verify we actually became root
        shell.send("whoami\n")
        matched, whoami_out = _read_until(["root", "failure"], timeout=10)
        if "failure" in whoami_out.lower() or "root" not in whoami_out:
          raise models.DeployerError(
              f"Failed to switch to root user via 'su -' on {vcf_ip}:"
              f" {whoami_out.strip()}"
          )
        logger.info("Successfully elevated to root user on %s.", vcf_ip)
      # 4. Execute configuration injection and service restart strictly as root
      commands = [
          (
              "files=('/opt/vmware/bringup/web/conf/application-prod.properties'"
              " '/etc/vmware/vcf/bringup/conf/application.properties'"
              " '/etc/vmware/vcf/domainmanager/application.properties')"
          ),
          (
              "for conf in \"${files[@]}\"; do if [ -f \"$conf\" ]; then grep"
              " -q '^vsan.esa.sddc.managed.disk.claim' \"$conf\" || echo"
              " 'vsan.esa.sddc.managed.disk.claim=true' >> \"$conf\"; grep -q"
              " '^sos.hcl.validation' \"$conf\" || echo"
              " 'sos.hcl.validation=false' >> \"$conf\"; fi; done"
          ),
          (
              "if systemctl list-unit-files | grep -q 'vcf-bringup'; then"
              " systemctl restart vcf-bringup; elif systemctl list-unit-files |"
              " grep -q 'domainmanager'; then systemctl restart domainmanager;"
              " fi"
          ),
          "echo BYPASS_DONE:$?",
      ]
      for cmd in commands:
        shell.send(cmd + "\n")
        time.sleep(0.5)
      # Wait for the completion flag
      matched, final_output = _read_until(["BYPASS_DONE:0"], timeout=60)
      if not matched:
        raise models.DeployerError(
            f"HCL bypass script execution failed on {vcf_ip}:\n{final_output.strip()}"
        )
      logger.info(
          "HCL bypass properties successfully written and bringup service"
          " restarted."
      )
    finally:
      if shell:
        shell.close()
      client.close()
