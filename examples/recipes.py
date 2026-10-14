"""Build, inspect, serialize, and reuse CyberChef-style recipes."""

from pychef import Chef, Recipe, bake


def main() -> None:
    # Step lists accept operation names or CyberChef-style dictionaries.
    steps = [
        "From Hex",
        {"op": "XOR", "args": [{"string": "42", "option": "Hex"}, "Standard", False]},
        {"op": "To Base64", "args": ["A-Za-z0-9+/="]},
    ]
    assert bake("0a272e2e2d", steps) == "SGVsbG8="

    # A Recipe is validated once and can then be executed many times.
    recipe = Recipe(steps)
    assert len(recipe) == 3
    assert [step.op for step in recipe.steps] == ["From Hex", "XOR", "To Base64"]

    # JSON round trip, e.g. to store recipes in configuration files.
    restored = Recipe.from_json(recipe.to_json())
    assert restored.to_config() == recipe.to_config()

    # A Chef bundles the engine settings for repeated execution.
    chef = Chef()
    for payload in ("0a272e2e2d", "0a272e2e2d"):
        assert chef.bake(payload, restored) == "SGVsbG8="

    result = chef.bake_result("0a272e2e2d", recipe, trace=True)
    print(f"Result: {result.result!r} after {result.progress} steps in {result.duration_ms:.2f} ms")
    for step in result.trace:
        print(f"  {step.operation}: {step.input_size} -> {step.output_size} bytes")


if __name__ == "__main__":
    main()
