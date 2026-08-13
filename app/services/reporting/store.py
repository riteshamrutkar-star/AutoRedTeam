from app.schemas.evaluation import EvaluationInput, EvaluationResult


class EvaluationStore:
    """In-memory store for active session evaluation context (no persistent database)."""

    def __init__(self) -> None:
        self._active_input: EvaluationInput | None = None
        self._active_result: EvaluationResult | None = None
        self._secondary_result: EvaluationResult | None = None

    def set_active(self, input_data: EvaluationInput, result: EvaluationResult) -> None:
        """Sets the current active evaluation run context."""
        self._active_input = input_data
        self._active_result = result

    def get_active_result(self) -> EvaluationResult | None:
        """Returns current active evaluation result."""
        return self._active_result

    def get_active_input(self) -> EvaluationInput | None:
        """Returns current active evaluation input data."""
        return self._active_input

    def set_secondary(self, result: EvaluationResult) -> None:
        """Sets secondary evaluation result for side-by-side comparison."""
        self._secondary_result = result

    def get_secondary_result(self) -> EvaluationResult | None:
        """Returns secondary comparison evaluation result."""
        return self._secondary_result

    def clear(self) -> None:
        """Clears stored evaluation objects."""
        self._active_input = None
        self._active_result = None
        self._secondary_result = None


# Singleton instance
evaluation_store = EvaluationStore()
