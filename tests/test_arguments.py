import pytest

from genmap.errors import ArgumentError
from genmap.nmap.arguments import review_arguments, tokenize_arguments


def test_tokenizer_handles_quotes_and_windows_paths():
    tokens = tokenize_arguments(r'--script-args-file "C:\Users\me\args file.txt" --datadir C:\nmap\data -T4')
    assert tokens == ["--script-args-file", r"C:\Users\me\args file.txt", "--datadir", r"C:\nmap\data", "-T4"]


def test_tokenizer_single_quotes_and_empty_values():
    assert tokenize_arguments("--data-string 'hello world' --x ''") == ["--data-string", "hello world", "--x", ""]


def test_unterminated_quote():
    with pytest.raises(ArgumentError):
        tokenize_arguments('--data-string "oops')


@pytest.mark.parametrize(
    "text",
    ["-oX out.xml", "-oN=x", "-oAbase", "--append-output", "-iL list.txt", "--resume old.xml", "--stats-every=5s", "-h", "--interactive"],
)
def test_managed_options_are_rejected(text):
    with pytest.raises(ArgumentError):
        review_arguments(text)


def test_shell_metacharacters_are_just_text():
    review = review_arguments("--data-string ';rm -rf /' --script-args 'a=$(id)'")
    assert review.tokens == ["--data-string", ";rm -rf /", "--script-args", "a=$(id)"]


def test_control_characters_rejected():
    with pytest.raises(ArgumentError):
        review_arguments("--data-string a\x07b")


def test_stray_values_are_flagged_as_extra_targets():
    review = review_arguments("--max-retries 2 10.0.0.9")
    assert review.tokens[-1] == "10.0.0.9"
    assert review.warnings and "additional target" in review.warnings[0]


def test_empty():
    assert review_arguments("   ").tokens == []
