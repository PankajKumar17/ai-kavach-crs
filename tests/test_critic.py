from pathlib import Path

from ai_kavach.critic import evaluate_patch_with_critic
from ai_kavach.patch_gen.models import Patch
from ai_kavach.rca import RootCauseReport


def test_critic_approve(mocker):
    # Mock LLM client
    mock_client = mocker.MagicMock()
    mock_client.create_message.return_value = {
        "content": [{"type": "text", "text": "APPROVE"}],
        "stop_reason": "end_turn",
    }
    mocker.patch("ai_kavach.critic.create_client", return_value=mock_client)

    patch = Patch(Path("vuln.c"), "diff")
    rca = RootCauseReport("buffer-overflow", "CWE-121", "crash_site", ["func"])

    result = evaluate_patch_with_critic(patch, rca, "clean", "clean")
    assert result is None


def test_critic_concern(mocker):
    # Mock LLM client
    mock_client = mocker.MagicMock()
    mock_client.create_message.return_value = {
        "content": [{"type": "text", "text": "CONCERN: This just adds a sleep()."}],
        "stop_reason": "end_turn",
    }
    mocker.patch("ai_kavach.critic.create_client", return_value=mock_client)

    patch = Patch(Path("vuln.c"), "diff")
    rca = RootCauseReport("buffer-overflow", "CWE-121", "crash_site", ["func"])

    result = evaluate_patch_with_critic(patch, rca, "clean", "clean")
    assert result == "This just adds a sleep()."
