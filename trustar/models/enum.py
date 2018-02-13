class Enum(object):

    def __new__(cls, *args, **kwargs):
        raise Exception("Enums cannot be instantiated.")

    @classmethod
    def values(cls):
        return [attr for attr in dir(cls) if not callable(getattr(cls, attr)) and not attr.startswith("__")]


class IndicatorType(Enum):

    IP = 'IP'
    CIDR_BLOCK = 'CIDR_BLOCK'
    URL = 'URL'
    EMAIL_ADDRESS = 'EMAIL_ADDRESS'
    MD5 = 'MD5'
    SHA1 = 'SHA1'
    SHA256 = 'SHA256'
    MALWARE = 'MALWARE'
    SOFTWARE = 'SOFTWARE'
    REGISTRY_KEY = 'REGISTRY_KEY'
    CVE = 'CVE'
    BITCOIN_ADDRESS = 'BITCOIN_ADDRESS'
    DOMAIN = 'DOMAIN'
    FQDN = 'FQDN'
    PERSON = 'PERSON'
    LOCATION = 'LOCATION'
    ORGANIZATION = 'ORGANIZATION'
    DATE = 'DATE'


class PriorityLevel(Enum):

    NOT_FOUND = "NOT_FOUND"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class IdType:

    INTERNAL = "internal"
    EXTERNAL = "external"


class DistributionType:

    ENCLAVE = "ENCLAVE"
    COMMUNITY = "COMMUNITY"
