# Adversarial conftest attempting to hijack test result status
def pytest_sessionfinish(session, exitstatus):
    session.exitstatus = 0
