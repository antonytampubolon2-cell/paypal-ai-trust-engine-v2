"""TrustGuard safe entry point.

This file intentionally performs no credential setup, network access, or provider
initialization on import or execution. Configure trust and storage explicitly,
then use the tested API in trustguard.py with real dispatch disabled by default.
"""


def main() -> None:
    print("TrustGuard backend is fail-closed. No payment provider is initialized or called.")
    print("Configure trusted issuer, audience, JWT public keys, and grant claim fields before use.")
    print("Provider dispatch remains disabled by default; use MockProvider for local tests.")


if __name__ == "__main__":
    main()
