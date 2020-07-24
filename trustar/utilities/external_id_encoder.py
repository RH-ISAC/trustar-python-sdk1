# encoding = utf-8

""" An object that encodes TruSTAR external IDs. """

import base64
from logging import getLogger
import uuid

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from logging import Logger

logger = getLogger(__name__)                                    # type: Logger

__ARBITRARY_SEED = 'f541adc0-f8b4-42a3-a1d9-fbcbfb2820a5'
ENCLAVE_UUID_NAMESPACE = uuid.UUID(__ARBITRARY_SEED)

class ExternalIdEncoder:
    """ Encodes eternal IDs for TruSTAR reports.
    External IDs need to:
    - calculate to the same thing every time, given the same inputs.
    - be url-encodeable. (some endpoints use them in query-string-params). """

    def __init__(self, exception_if_reversible_fails=True         # type: bool
                 ):
        self.exc_if_rev_fail = exception_if_reversible_fails      # type: bool

    @staticmethod
    def irreversible(enclave_id, external_id):       # type: (str, str) -> str
        """ Uses enclave ID and desired external ID to produce an
        external ID that will always work with Station. """

        try:
            namespace_uuid = uuid.UUID(enclave_id)
        except ValueError:
            # if the enclave_id was not a valid UUID, hash it to create one.
            # some staging enclave_ids are not valid UUIDs.
            namespace_uuid = uuid.uuid5(ENCLAVE_UUID_NAMESPACE,
                                        enclave_id)

        return str(uuid.uuid5(namespace_uuid, external_id))

    def reversible(self, enclave_id, external_id):   # type: (str, str) -> str
        """ Makes a reversible external ID. """
        s = enclave_id + '|' + external_id                       # type: str
        b = s.encode('utf-8')                                    # type: bytes
        encoded = base64.b64encode(b)                            # type: bytes
        stringified_b64_encoding = encoded.decode('utf-8')       # type: str
        if self.reverse(stringified_b64_encoding) != s:
            msg = ("External ID encoder's 'reversible' method produced an  "
                   "external ID that its 'reverse' method did not "
                   "successfully reverse. String: '{}'.  Stringified "
                   "encoding:  '{}'."
                   .format(s, stringified_b64_encoding))
            logger.error(msg)
            if self.exc_if_rev_fail:
                raise Exception(msg)

        return stringified_b64_encoding

    @staticmethod
    def reverse(stringified_b64_encoding):                # type: (str) -> str
        """ Reverses an external ID created by the 'reversible' method. """
        b64_encoding = stringified_b64_encoding.encode('utf-8')  # type: bytes
        b = base64.b64decode(b64_encoding)                       # type: bytes
        s = b.decode('utf-8')
        return s
