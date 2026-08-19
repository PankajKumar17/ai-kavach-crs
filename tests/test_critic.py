from pathlib import Path

from ai_kavach.critic import evaluate_patch_with_critic
from ai_kavach.patch_gen.models import Patch
from ai_kavach.rca import RootCauseReport


def test_critic_approve(mocker):
    # Mock Anthropic
    mock_client = mocker.patch("ai_kavach.critic.anthropic.Anthropic")
    mock_msg = mocker.MagicMock()
    mock_msg.content = [mocker.MagicMock(text="APPROVE")]
    mock_client.return_value.messages.create.return_value = mock_msg
    
    patch = Patch(Path("vuln.c"), "diff")
    rca = RootCauseReport("buffer-overflow", "vuln.c", 10, False)
    
    result = evaluate_patch_with_critic(patch, rca, "clean", "clean")
    assert result is None
    

def test_critic_concern(mocker):
    # Mock Anthropic
    mock_client = mocker.patch("ai_kavach.critic.anthropic.Anthropic")
    mock_msg = mocker.MagicMock()
    mock_msg.content = [mocker.MagicMock(text="CONCERN: This just adds a sleep().")]
    mock_client.return_value.messages.create.return_value = mock_msg
    
    patch = Patch(Path("vuln.c"), "diff")
    rca = RootCauseReport("buffer-overflow", "vuln.c", 10, False)
    
    result = evaluate_patch_with_critic(patch, rca, "clean", "clean")
    assert result == "This just adds a sleep()."
