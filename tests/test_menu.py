"""The interactive menu (`arer` with no arguments, or `arer menu`) and the commands it must not break."""
import re
from email.message import EmailMessage

import click
import pytest
from click.testing import CliRunner

from arer import menu
from arer.cli import main

ANSI = re.compile(r"\x1b\[[0-9;]*m")


@pytest.fixture
def env(tmp_path):
    return {"PHISHSCOPE_FEEDS": str(tmp_path / "nofeeds"), "PHISHSCOPE_HISTORY": str(tmp_path / "h" / "h.db")}


def mail(path, frm="Sam <sam@example.org>", subject="Lunch", body="Lunch on Friday?", bad=False):
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = frm, "me@example.org", subject
    m["Date"], m["Message-ID"] = "Mon, 05 Jan 2026 09:00:00 +0000", f"<{abs(hash(str(path)))}@example.org>"
    m.set_content(body)
    if bad:
        m.add_attachment(b"MZ\x90\x00" + b"0" * 40, maintype="application", subtype="octet-stream", filename="invoice.pdf.exe")
    path.write_bytes(m.as_bytes())
    return path


def item(title: str) -> int:
    return [a.title for a in menu.ACTIONS].index(title) + 1


def run(env, text):
    return CliRunner().invoke(main, ["menu"], input=text, env=env)


# ------------------------------- look and feel ----------------------------------- #
def test_banner_is_plain_and_reserves_logo_space(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    rows = menu.banner_lines()
    assert all(not ANSI.search(t) for t, _ in rows)
    assert all(t.startswith(" " * menu.LOGO_WIDTH) for t, _ in rows)            # empty logo: space is kept free
    assert any("__" in t for t, kind in rows if kind == "title")
    assert max(len(t) for t, _ in rows) < 70

def test_a_taller_logo_is_drawn_left_and_the_title_is_centred(monkeypatch):
    monkeypatch.setattr(menu, "LOGO", [f"L{i}" for i in range(11)])
    rows = menu.banner_lines()
    assert len(rows) == 11 and rows[0][0].startswith("L0") and rows[10][0].startswith("L10")
    titles = [i for i, (_, k) in enumerate(rows) if k == "title"]
    assert titles[0] > 0 and titles[-1] < 10

def test_clean_path_handles_pasted_and_dragged_paths(tmp_path):
    assert str(menu.clean_path("  '/tmp/a b/x.eml'  ")) == "/tmp/a b/x.eml"
    assert str(menu.clean_path('"/tmp/a b/x.eml"')) == "/tmp/a b/x.eml"
    assert str(menu.clean_path(r"/tmp/a\ b/x.eml")) == "/tmp/a b/x.eml"
    assert not str(menu.clean_path("~/x.eml")).startswith("~")


# ------------------------------- menu basics ------------------------------------- #
def test_menu_lists_every_action_and_quits(env):
    r = run(env, "0\n")
    assert r.exit_code == 0 and "What would you like to do?" in r.output and "Goodbye" in r.output
    for a in menu.ACTIONS:
        assert a.title in r.output

def test_bad_input_is_explained_and_the_menu_stays_open(env):
    r = run(env, "x\n99\n\n0\n")
    assert r.exit_code == 0 and r.output.count("Please type a number") == 3 and r.output.count("What would you like") == 4

def test_end_of_input_exits_cleanly(env):
    r = run(env, "")
    assert r.exit_code == 0 and "Goodbye" in r.output

def test_bare_arer_without_a_terminal_still_shows_help():
    r = CliRunner().invoke(main, [])
    assert r.exit_code == 0 and "Commands:" in r.output and "What would you like" not in r.output

def test_every_typed_command_is_still_there():
    r = CliRunner().invoke(main, ["--help"])
    for c in ("scan", "eval", "label", "history", "feeds", "parse", "menu"):
        assert c in r.output


# ----------------------------------- scan flow ------------------------------------ #
def test_scan_one_file_shows_the_equivalent_command_and_the_report(tmp_path, env):
    f = mail(tmp_path / "m.eml")
    r = run(env, f"{item('Scan emails')}\n{f}\nn\nn\n0\n")
    assert r.exit_code == 0 and f"arer scan {f}" in r.output and "Verdict" in r.output

def test_scan_folder_offers_subfolders_and_one_line_output(tmp_path, env):
    (tmp_path / "box" / "inner").mkdir(parents=True)
    mail(tmp_path / "box" / "inner" / "a.eml"); mail(tmp_path / "box" / "inner" / "b.eml", subject="Notes")
    r = run(env, f"{item('Scan emails')}\n{tmp_path / 'box'}\ny\ny\nn\nn\n0\n")
    running = next(l for l in r.output.splitlines() if "Running:" in l)
    assert "Found 2 email(s)" in r.output and " -r" in running and " -q" in running
    assert "a.eml" in r.output and "b.eml" in r.output

def test_scan_empty_folder_is_explained(tmp_path, env):
    (tmp_path / "empty").mkdir()
    r = run(env, f"{item('Scan emails')}\n{tmp_path / 'empty'}\n0\n")
    assert "No emails" in r.output and r.exit_code == 0

def test_missing_path_is_explained_and_q_goes_back(env):
    r = run(env, f"{item('Scan emails')}\n/no/such/place.eml\nq\n0\n")
    assert "I cannot find" in r.output and r.exit_code == 0

def test_a_phishing_result_does_not_crash_the_menu(tmp_path, env):
    f = mail(tmp_path / "p.eml", frm="PayPal Support <x@paypa1-secure.com>", subject="Verify now", body="Go to http://1.2.3.4/login", bad=True)
    r = run(env, f"{item('Scan emails')}\n{f}\nn\nn\n0\n")           # scan exits with code 2 internally
    assert r.exit_code == 0 and r.output.count("What would you like") == 2 and "Goodbye" in r.output

def test_scan_can_save_to_history(tmp_path, env):
    f = mail(tmp_path / "m.eml")
    r = run(env, f"{item('Scan emails')}\n{f}\ny\nn\n0\n")
    assert "--save" in r.output and "history: saved" in r.output


# ---------------------------------- other flows ----------------------------------- #
def test_eval_refuses_a_folder_without_phish_and_legit(tmp_path, env):
    (tmp_path / "x").mkdir()
    r = run(env, f"{item('Measure accuracy')}\n1\n{tmp_path / 'x'}\n0\n")
    assert "nothing to compare" in r.output and r.exit_code == 0

def test_eval_runs_on_a_labeled_folder(tmp_path, env):
    for lab, subj in (("phish", "Verify now"), ("legit", "Lunch")):
        (tmp_path / "s" / lab).mkdir(parents=True)
        mail(tmp_path / "s" / lab / "a.eml", subject=subj, body=f"{subj} http://1.2.3.4/x" if lab == "phish" else "hi")
    r = run(env, f"{item('Measure accuracy')}\n1\n{tmp_path / 's'}\nn\n0\n")
    assert "Detection by level" in r.output and "1 phishing, 1 legitimate" in r.output

def test_label_flow_labels_a_file(tmp_path, env):
    f = mail(tmp_path / "m.eml")
    r = run(env, f"{item('Label an email')}\n{f}\n1\nlooks fake\n0\n")
    assert "arer label" in r.output and "-> phish" in r.output

def test_label_flow_rejects_junk(env):
    r = run(env, f"{item('Label an email')}\nnot-a-file\n0\n")
    assert "neither an existing file nor" in r.output

def test_blocklist_status_flow(env):
    r = run(env, f"{item('Blocklists')}\n1\n0\n")
    assert "arer feeds status" in r.output and "index:" in r.output

def test_internet_step_needs_confirmation(env):
    r = run(env, f"{item('Blocklists')}\n2\nn\n0\n")
    assert "uses the internet" in r.output and "arer feeds update" not in r.output

def test_help_lists_the_matching_commands(env):
    r = run(env, f"{item('Help')}\n0\n")
    assert "arer scan PATH" in r.output and "arer label FILE" in r.output


# -------------------------------- expandability (AI) ------------------------------ #
def test_a_new_action_appears_with_the_next_number(monkeypatch, env):
    seen = []
    extra = menu.Action("Explain a verdict", "future AI option", lambda: seen.append(1))
    monkeypatch.setattr(menu, "ACTIONS", menu.ACTIONS + [extra])
    n = len(menu.ACTIONS)
    r = run(env, f"{n}\n0\n")
    assert "Explain a verdict" in r.output and seen == [1]

def test_ctrl_c_inside_an_action_returns_to_the_menu(monkeypatch, env):
    def boom():
        raise click.Abort()
    monkeypatch.setattr(menu, "ACTIONS", [menu.Action("Boom", "x", boom)])
    r = run(env, "1\n0\n")
    assert "Cancelled" in r.output and r.output.count("What would you like") == 2 and r.exit_code == 0
