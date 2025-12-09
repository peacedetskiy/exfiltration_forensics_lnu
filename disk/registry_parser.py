import io
import re
from Registry import Registry
from datetime import datetime
from utils.logger import setup_logger

logger = setup_logger(log_file="logs/disk.log")

USB_EVENT_RE = re.compile(
    r'usb\s+\d+-\d+:.*',
    re.IGNORECASE
)

ID_RE = re.compile(
    r'(idVendor|idProduct|Manufacturer|Product|SerialNumber)=(\S+)',
    re.IGNORECASE
)

DATE_RE = re.compile(
    r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
)


def parse_system_hive(entry):
    """Parse Windows SYSTEM hive for USB history."""
    usb_history = []
    try:
        data = b""
        offset = 0
        while offset < entry.info.meta.size:
            chunk = entry.read_random(offset, 1024 * 1024)
            if not chunk:
                break
            data += chunk
            offset += len(chunk)

        try:
            reg = Registry.Registry(io.BytesIO(data))
        except Registry.RegistryParseException as e:
            logger.warning(f"Failed to parse SYSTEM hive: {e}")
            return usb_history

        key_path = r"ControlSet001\Enum\USBSTOR"
        try:
            key = reg.open(key_path)
            for subkey in key.subkeys():
                device_name = subkey.name()
                for instance in subkey.subkeys():
                    values = {v.name(): v.value() for v in instance.values()}
                    usb_history.append({
                        "device_name": device_name,
                        "instance": instance.name(),
                        "values": values
                    })
        except Registry.RegistryKeyNotFoundException:
            logger.debug(f"USBSTOR key not found in SYSTEM hive")
    except Exception as e:
        logger.warning(f"Error reading SYSTEM hive entry: {e}")

    return usb_history


def extract_windows_usb(entry, full_path):
    """Detect Windows SYSTEM hive files and parse USB artifacts."""
    normalized = full_path.lower()
    if normalized.endswith("/windows/system32/config/system") or \
       normalized.endswith("/windows/system32/config/system (deleted)"):
        return parse_system_hive(entry)
    return []


def extract_linux_usb(entry, full_path):
    """Extract USB info from Linux logs."""
    normalized = full_path.lower()
    linux_targets = [
        "/var/log/syslog",
        "/var/log/messages",
        "/var/log/kern.log"
    ]

    if not any(normalized.endswith(t) for t in linux_targets):
        return []

    try:
        data = entry.read_random(0, entry.info.meta.size)
    except Exception as e:
        logger.debug(f"Cannot read Linux log {full_path}: {e}")
        return []

    return parse_linux_usb_logs(data)


def parse_linux_usb_logs(data):
    """Parse USB insertion/removal events from Linux logs."""
    usb_entries = []
    current = {
        "timestamp": None,
        "vendor": None,
        "product": None,
        "manufacturer": None,
        "description": None,
        "serial": None
    }

    try:
        text = data.decode("utf-8", errors="ignore")
    except Exception as e:
        logger.warning(f"Failed to decode Linux log data: {e}")
        return usb_entries

    for line in text.splitlines():
        if not USB_EVENT_RE.search(line):
            continue

        ts = DATE_RE.search(line)
        if ts:
            try:
                current["timestamp"] = datetime.strptime(ts.group(1), "%b %d %H:%M:%S").isoformat()
            except Exception:
                current["timestamp"] = ts.group(1)

        ids = ID_RE.findall(line)
        for field, val in ids:
            fld = field.lower()
            if fld == "idvendor":
                current["vendor"] = val
            elif fld == "idproduct":
                current["product"] = val
            elif fld == "manufacturer":
                current["manufacturer"] = val
            elif fld == "product":
                current["description"] = val
            elif fld == "serialnumber":
                current["serial"] = val

        if current["vendor"] or current["product"]:
            usb_entries.append(current.copy())
            current = {k: None for k in current}

    return usb_entries


def extract_usb_artifacts(entry, full_path, fs_type):
    """Detect filesystem type and extract USB artifacts accordingly."""
    fs_type = fs_type.lower()
    if "ntfs" in fs_type or "fat" in fs_type or "exfat" in fs_type:
        return extract_windows_usb(entry, full_path)
    if "linux" in fs_type:
        return extract_linux_usb(entry, full_path)
    logger.debug(f"No USB extraction rules for filesystem type: {fs_type}")
    return []
