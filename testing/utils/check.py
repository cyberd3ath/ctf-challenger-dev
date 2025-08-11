def check(condition, success_message, failure_message, throw_exception=False):
    """
    Check a condition and print a success or failure message.

    Args:
        condition (bool): The condition to check.
        success_message (str): The message to print if the condition is True.
        failure_message (str): The message to print if the condition is False.
    """
    if condition:
        print(f"Success: {success_message}")
        return True

    else:
        print(f"Failure: {failure_message}")
        if throw_exception:
            raise Exception(failure_message)

        return False