import logging

from config import (
    LDAP_ENABLE,
    LDAP_URL,
    LDAP_USER_BASE,
    LDAP_IPA_ADMIN_GROUPS,
    LDAP_IPA_SUPERUSER_GROUPS,
    LDAP_IPA_GROUPS,
)


if LDAP_ENABLE:
    from nldcsc.auth.ldap_client import LDAPClient


# logging.setLoggerClass(AppLogger)
logger = logging.getLogger(__name__)


# @auth.route("/login", methods=["GET", "POST"])
def do_login(u_id: str, pwd: str) -> tuple:
    """Perforn LDAP login.
    On success return username.

    Args:
        u_id (str): userid
        pwd (str): user password

    Returns:
        tuple: success, username
    """
    if LDAP_ENABLE:
        ldap_client = LDAPClient(
            url=LDAP_URL,
            username=u_id,
            password=pwd,
            ldap_user_base=LDAP_USER_BASE,
            ldap_ipa_admin_groups=LDAP_IPA_ADMIN_GROUPS,
            ldap_ipa_superuser_groups=LDAP_IPA_SUPERUSER_GROUPS,
            ldap_ipa_groups=LDAP_IPA_GROUPS,
        )

        try:
            if ldap_client.validate_credentials():
                return ldap_client.validate_user()

            else:
                logger.warning(f"Invalid LDAP credentials for user {u_id}...")

        except Exception as err:
            # LDAP login failed.
            logger.error(f"LDAP Login resulted in error: {err}")
            logger.exception(err)
            pass

    return False, None
