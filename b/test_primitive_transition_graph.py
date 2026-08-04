from memory.primitive_transition_graph import (
    TEMPLATE_CAPABILITY_STATE_ORDER,
    PrimitiveTransitionGraph,
)


LEGACY_SSTI_REFLECTION_TARGETS = [
    "ssti_execution",
    "blind_ssti",
    "template_access",
    "configuration_disclosure",
    "file_read",
    "command_execution",
]


def test_all_capability_transition_endpoints_exist():
    graph = PrimitiveTransitionGraph()
    state_ids = {item.id for item in graph.get_capability_primitives()}

    for transition in graph.get_capability_transitions():
        assert transition.from_state in state_ids
        assert transition.to_state in state_ids


def test_capability_transitions_do_not_skip_intermediate_states():
    graph = PrimitiveTransitionGraph()
    positions = {
        state_id: index
        for index, state_id in enumerate(TEMPLATE_CAPABILITY_STATE_ORDER)
    }

    for transition in graph.get_capability_transitions():
        assert positions[transition.to_state] == positions[transition.from_state] + 1


def test_legacy_interfaces_remain_compatible():
    graph = PrimitiveTransitionGraph()

    assert graph.get_next_primitives("ssti_reflection") == LEGACY_SSTI_REFLECTION_TARGETS
    assert graph.get_next_primitives("unknown") == []
    assert graph.get_next_state("ssti_reflection") == "ssti_execution"


def test_rich_transition_and_primitive_contracts():
    graph = PrimitiveTransitionGraph()
    primitive = graph.get_capability_primitive("method_available")
    transition = graph.get_transition("method_available", "execution_confirmed")

    assert primitive is not None
    assert set(primitive.to_dict()) == {
        "id",
        "description",
        "required_observations",
        "success_indicators",
        "failure_indicators",
    }
    assert primitive.required_observations
    assert primitive.success_indicators
    assert primitive.failure_indicators

    assert transition is not None
    assert set(transition.to_dict()) == {
        "from_state",
        "to_state",
        "prerequisites",
        "expected_observations",
        "invalid_conditions",
        "planner_hint",
    }
    assert transition.prerequisites
    assert transition.expected_observations
    assert transition.invalid_conditions
    assert transition.planner_hint
