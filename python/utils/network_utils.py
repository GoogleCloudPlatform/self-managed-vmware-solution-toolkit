"""Client-independent network routing and SSL socket inspection utilities.

Provides stateless domain helper routines for unified VLAN/CIDR routing
deduction across primary and dynamic alias interfaces, GCP reserved address
validation, and remote SSL SHA-256 certificate fingerprint capture.
"""

import hashlib
import ipaddress
import logging
import os
import socket
import ssl
from typing import Any, Optional, Tuple

import constants
import models

logger = logging.getLogger(constants.DeployerDefaults.LOGGER_NAME)


def extract_vlan_cidr_and_routing(
    vcf_ip: str, target_details: models.GCEInstanceDetails, gcp_client: Any
) -> Tuple[int, str, str, str]:
  """Unified extraction of VLAN ID, CIDR range, Gateway, and Netmask in one call.

  Evaluates primary NIC (VLAN 0) and dynamic alias NICs attached to the
  primary interface. Identifies enclosing subnetwork CIDR, verifies IP is not
  a reserved GCP address, and derives gateway and subnet mask simultaneously.

  Args:
      vcf_ip: Configured VCF installer static IPv4 address.
      target_details: Cached GCEInstanceDetails for the target ESXi host.
      gcp_client: Initialized GCPClient to query subnet CIDRs if unpopulated.

  Returns:
      Tuple of (vlan_id, cidr_range, netmask, gateway_ip).

  Raises:
      models.ValidationError: If IP syntax is malformed or unreachable.
  """
  logger.info(
      "Performing unified VLAN/CIDR and routing extraction for IP %s against"
      " host '%s'...",
      vcf_ip,
      target_details.instance_resource_string,
  )
  try:
    target_addr = ipaddress.IPv4Address(vcf_ip)
  except ValueError as exc:
    raise models.ValidationError(
        f"Configured vcf_installer_ip '{vcf_ip}' is not valid IPv4: {exc}"
    ) from exc

  for subnet_info in target_details.subnetworks:
    if not subnet_info.cidr:
      subnet_info.cidr = gcp_client.fetch_subnetwork_cidr(
          subnet_info.subnetwork_uri
      )

    cidr = subnet_info.cidr
    try:
      net = ipaddress.IPv4Network(cidr, strict=False)
    except ValueError:
      continue

    if target_addr in net:
      # Check GCP reserved addresses (first two and last two IPs in block)
      network_ip = net.network_address
      gateway_ip = net.network_address + 1
      broadcast_ip = net.broadcast_address
      second_to_last = net.broadcast_address - 1

      if target_addr in (
          network_ip,
          gateway_ip,
          broadcast_ip,
          second_to_last,
      ):
        raise models.ValidationError(
            f"VCF installer IP '{vcf_ip}' falls on a reserved GCP subnetwork"
            f" address in CIDR '{cidr}'!"
        )

      vlan_id = subnet_info.vlan_id  # 0 for primary NIC, >0 for dynamic NICs
      netmask = str(net.netmask)
      gateway = str(gateway_ip)

      logger.info(
          "Subnet containment verified: IP %s matched CIDR %s -> VLAN ID: %d,"
          " Netmask: %s, Gateway: %s.",
          vcf_ip,
          cidr,
          vlan_id,
          netmask,
          gateway,
      )
      return vlan_id, cidr, netmask, gateway

  raise models.ValidationError(
      f"Configured VCF installer IP '{vcf_ip}' does not fall within any primary"
      " or dynamic NIC subnetwork ranges attached to target host"
      f" '{target_details.instance_resource_string}'!"
  )


def capture_ssl_thumbprint(target_url: str) -> str:
  """Opens HTTPS socket connection to target host port 443 to capture SHA-256 hash.

  Args:
      target_url: HTTPS web domain or URL string of OVA depot distribution host.

  Returns:
      Colon-separated SHA-256 hexadecimal certificate thumbprint.

  Raises:
      models.ValidationError: If no SSL certificate is returned by server.
      models.RetryableError: If network socket connection fails or times out.
  """
  hostname = (
      target_url.replace("https://", "")
      .replace("http://", "")
      .split("/")[0]
      .split(":")[0]
  )
  logger.info(
      "Connecting to %s:%d to capture SSL SHA-256 thumbprint...",
      hostname,
      constants.NetworkingDefaults.HTTPS_PORT,
  )
  try:
    if hasattr(ssl, "_create_unverified_context"):
      ctx = ssl._create_unverified_context()
    else:
      ctx = ssl.create_default_context()
      ctx.check_hostname = False
      ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection(
        (hostname, constants.NetworkingDefaults.HTTPS_PORT),
        timeout=constants.NetworkingDefaults.SSL_TIMEOUT_SECONDS,
    ) as sock:
      with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
        cert_der = ssock.getpeercert(binary_form=True)
        if not cert_der:
          raise models.ValidationError(
              f"No SSL certificate returned by server '{hostname}:443'."
          )
        sha256_hash = hashlib.sha256(cert_der).hexdigest().upper()
        thumbprint = ":".join(
            sha256_hash[i : i + 2] for i in range(0, len(sha256_hash), 2)
        )
        logger.info("Captured SSL thumbprint for %s: %s", hostname, thumbprint)
        return thumbprint
  except Exception as exc:  # pylint: disable=broad-exception-caught
    if isinstance(exc, models.ValidationError):
      raise exc
    raise models.RetryableError(
        f"Failed to connect to '{hostname}:443' to capture SSL SHA-256"
        f" thumbprint: {exc}"
    ) from exc


class _HostOverrideSSLContext(ssl.SSLContext):
  """SSLContext subclass supporting SNI/hostname override and SHA-256 thumbprint pinning."""

  _override_server_hostname: Optional[str] = None
  _expected_thumbprint_hex: Optional[str] = None

  def wrap_socket(
      self,
      sock: socket.socket,
      server_side: bool = False,
      do_handshake_on_connect: bool = True,
      suppress_ragged_eofs: bool = True,
      server_hostname: Optional[str] = None,
      session: Optional[ssl.SSLSession] = None,
  ) -> ssl.SSLSocket:
    effective_hostname = self._override_server_hostname or server_hostname
    ssock = super().wrap_socket(
        sock,
        server_side=server_side,
        do_handshake_on_connect=do_handshake_on_connect,
        suppress_ragged_eofs=suppress_ragged_eofs,
        server_hostname=effective_hostname,
        session=session,
    )
    if self._expected_thumbprint_hex and do_handshake_on_connect:
      cert_der = ssock.getpeercert(binary_form=True)
      actual_hex = (
          hashlib.sha256(cert_der).hexdigest().upper() if cert_der else ""
      )
      if actual_hex != self._expected_thumbprint_hex:
        ssock.close()
        raise ssl.SSLCertVerificationError(
            "Offline depot SSL certificate SHA-256 thumbprint mismatch:"
            f" expected {self._expected_thumbprint_hex}, got {actual_hex}."
        )
    return ssock


def create_depot_ssl_context(
    fqdn_host: Optional[str] = None,
    expected_thumbprint: Optional[str] = None,
    ca_bundle_path: Optional[str] = None,
) -> ssl.SSLContext:
  """Builds an SSLContext for Offline Depot HTTPS connections over PSC or DNS.

  Verifies the X.509 certificate chain and hostname when connecting to a
  production Offline Depot domain (*.selfmanagedvmwareengine.goog, backed by
  Google Trust Services) or when a custom CA bundle is configured via
  ca_bundle_path / OFFLINE_DEPOT_CA_BUNDLE. When connecting via a PSC IP with
  a Host header (fqdn_host), overrides SNI/hostname verification to fqdn_host.
  Also enforces SHA-256 certificate thumbprint pinning when expected_thumbprint
  is provided.

  Args:
      fqdn_host: Optional logical FQDN or hostname of the Offline Depot server.
      expected_thumbprint: Optional colon-separated or raw hex SHA-256 SSL
        certificate thumbprint to pin.
      ca_bundle_path: Optional path to a custom trusted CA PEM bundle.

  Returns:
      Configured ssl.SSLContext instance.
  """
  clean_fqdn = fqdn_host.strip().rstrip(".") if fqdn_host else None
  is_ip_host = False
  if clean_fqdn:
    try:
      ipaddress.ip_address(clean_fqdn)
      is_ip_host = True
    except ValueError:
      is_ip_host = False

  effective_ca_bundle = ca_bundle_path or os.environ.get(
      constants.ValidationRules.OFFLINE_DEPOT_CA_BUNDLE_ENV_VAR
  )
  should_verify_ca = bool(effective_ca_bundle) or bool(
      clean_fqdn
      and not is_ip_host
      and clean_fqdn.lower().endswith(
          constants.ValidationRules.PROD_DEPOT_DOMAIN_SUFFIX
      )
  )

  ctx = _HostOverrideSSLContext(ssl.PROTOCOL_TLS_CLIENT)
  if clean_fqdn and not is_ip_host:
    ctx._override_server_hostname = clean_fqdn

  if expected_thumbprint:
    clean_tp = expected_thumbprint.replace(":", "").strip().upper()
    if clean_tp:
      ctx._expected_thumbprint_hex = clean_tp

  if should_verify_ca:
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = bool(clean_fqdn and not is_ip_host)
    if effective_ca_bundle:
      ctx.load_verify_locations(cafile=effective_ca_bundle)
    else:
      ctx.load_default_certs()
  else:
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

  return ctx


def validate_subnet_cidr_size(cidr: str) -> None:
  """Validates CIDR format and enforces minimum standard GCP subnet size of /29 (4 usable IPs).

  Args:
      cidr: IPv4 CIDR range string (e.g. '10.0.100.0/29').

  Raises:
      models.ValidationError: If CIDR syntax is invalid or prefix length > 29.
  """
  if not cidr or not isinstance(cidr, str):
    raise models.ValidationError("Subnet CIDR is missing or empty!")

  try:
    network = ipaddress.IPv4Network(cidr.strip(), strict=False)
  except ValueError as exc:
    raise models.ValidationError(
        f"Invalid subnet CIDR format '{cidr}': {exc}"
    ) from exc

  if network.prefixlen > constants.OfflineDepotDefaults.MAX_SUBNET_PREFIX_LEN:
    raise models.ValidationError(
        f"Subnet CIDR '{cidr}' (/{network.prefixlen}) is too small! "
        "Google Cloud standard subnets require a minimum size of /29 (8 total IPs, 4 usable)."
    )


def validate_subnet_cidr_not_in_use(
    target_cidr: str,
    existing_subnets: Any,
    gcp_client: Any,
) -> None:
  """Validates that target CIDR does not overlap with or match any existing subnetworks.

  Args:
      target_cidr: Target IPv4 CIDR range string (e.g. '10.0.100.0/29').
      existing_subnets: Iterable of SubnetworkInfo objects representing existing subnets.
      gcp_client: Initialized GCPClient to fetch subnet CIDRs if unpopulated.

  Raises:
      models.ValidationError: If target CIDR syntax is invalid, or if it overlaps
        with or is already used by an existing subnet.
  """
  if not target_cidr or not isinstance(target_cidr, str):
    return

  try:
    target_net = ipaddress.IPv4Network(target_cidr.strip(), strict=False)
  except ValueError as exc:
    raise models.ValidationError(
        f"Invalid subnet CIDR format '{target_cidr}': {exc}"
    ) from exc

  checked_uris = set()
  for subnet_info in existing_subnets or []:
    if not subnet_info or not getattr(subnet_info, "subnetwork_uri", None):
      continue
    sub_uri = subnet_info.subnetwork_uri
    if sub_uri in checked_uris:
      continue
    checked_uris.add(sub_uri)

    if not getattr(subnet_info, "cidr", None):
      subnet_info.cidr = gcp_client.fetch_subnetwork_cidr(sub_uri)

    if subnet_info.cidr:
      try:
        existing_net = ipaddress.IPv4Network(
            subnet_info.cidr.strip(), strict=False
        )
      except ValueError:
        continue

      if target_net.overlaps(existing_net):
        raise models.ValidationError(
            f"Configured offline depot subnet CIDR '{target_cidr}' overlaps with"
            f" or is already used by existing subnet '{sub_uri}'"
            f" with CIDR '{subnet_info.cidr}'!"
        )



