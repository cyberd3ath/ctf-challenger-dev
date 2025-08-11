import sys
import os
import time

TEST_UTILS_DIR = "/root/ctf-challenger/testing/utils"
BACKEND_DIR = "/root/ctf-challenger/backend"

sys.path.append(TEST_UTILS_DIR)
sys.path.append(BACKEND_DIR)

from mock_db import MockDatabase
from test_user_setup import test_user_setup
from create_user_config import create_user_config
from delete_user_config import delete_user_config


def test_backend_user_config_handling():
    """
    Test the create_user_config function.
    """

    with MockDatabase() as db_conn:
        user_id = test_user_setup(db_conn, "testuser", "testpassword")
        try:
            create_user_config(user_id, db_conn)

            assert os.path.exists(f"/etc/openvpn/ccd/{user_id}"), "\tCCD file not created"
            assert os.path.exists(f"/etc/openvpn/client-configs/{user_id}.ovpn"), "\tClient config file not created"
            assert os.path.exists(f"/etc/openvpn/easy-rsa/pki/issued/{user_id}.crt"), "\tClient certificate not created"
            assert os.path.exists(f"/etc/openvpn/easy-rsa/pki/private/{user_id}.key"), "\tClient key not created"

            print("\tUser configuration created successfully")

        except Exception as e:
            print(f"\tFailed to create user configuration: {e}")

        finally:
            delete_user_config(user_id)

            assert not os.path.exists(f"/etc/openvpn/ccd/{user_id}"), "\tCCD file not deleted"
            assert not os.path.exists(f"/etc/openvpn/client-configs/{user_id}.ovpn"), "\tClient config file not deleted"
            assert not os.path.exists(f"/etc/openvpn/easy-rsa/pki/issued/{user_id}.crt"), "\tClient certificate not deleted"
            assert not os.path.exists(f"/etc/openvpn/easy-rsa/pki/private/{user_id}.key"), "\tClient key not deleted"
            assert time.time() - os.path.getmtime(f"/etc/openvpn/easy-rsa/pki/issued/{user_id}.crt") < 5, "\tClient certificate not updated"

            print("\tUser configuration deleted successfully")



if __name__ == "__main__":
    test_backend_user_config_handling()