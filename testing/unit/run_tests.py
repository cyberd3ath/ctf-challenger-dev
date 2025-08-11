import time

from test_backend_challenge_handling import test_backend_challenge_handling
from test_backend_machine_template_handling import test_backend_machine_template_handling
from test_backend_user_config_handling import test_backend_user_config_handling


def run_all_tests():
    """
    Run all unit tests.
    """
    print("Testing the backend functionality")
    print("\n========================================")
    print("\nTesting the creation and deletion of user configurations")
    test_backend_user_config_handling()

    time.sleep(10)

    print("\nTesting the import and deletion of machine templates")
    test_backend_machine_template_handling()

    time.sleep(10)

    print("\nTesting the launch and stop of challenges")
    test_backend_challenge_handling()


if __name__ == "__main__":
    run_all_tests()
