def validate_all():
    try:
        validate(payload)
    except ValidationError as error:
        print("Invalid input", file=sys.stderr)
        sys.exit(error)

    try:
        validate(config)
    except ValidationError as error:
        print(f"Invalid config: {error}")
        sys.exit(-1)

    try:
        validate(response)
    except ValidationError:
        print("Invalid response")
        return False

    try:
        validate(state)
    except ValidationError:
        print("Invalid state")
        raise

    try:
        validate(other)
    except ValidationError:
        print("Validation failed")
