from email.message import EmailMessage

from click.testing import CliRunner

from arer.cli import main
from arer.config import load_config
from arer.evaluate import evaluate, render, wilson

cfg = load_config()


def write(path, frm, subject, body, reply_to=None, attach=False):
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = frm, "me@example.org", subject
    m["Date"], m["Message-ID"] = "Mon, 05 Jan 2026 09:00:00 +0000", f"<{abs(hash(subject))}@example.org>"
    if reply_to:
        m["Reply-To"] = reply_to
    m.set_content(body)
    if attach:
        m.add_attachment(b"MZ\x90\x00" + b"0" * 40, maintype="application", subtype="octet-stream", filename="invoice.pdf.exe")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(m.as_bytes())


def build(tmp_path):
    write(tmp_path / "phish" / "p1.eml", '"PayPal Support" <x@paypa1-secure.com>', "Verify now", "Go to http://1.2.3.4/login", "c@evil.example", True)
    write(tmp_path / "phish" / "p2.eml", "Bob <bob@example.net>", "hello", "nothing suspicious at all in here")   # a miss
    write(tmp_path / "legit" / "l1.eml", "Sam <sam@example.org>", "Lunch", "Lunch on Friday?")
    write(tmp_path / "legit" / "l2.eml", "Ann <ann@example.org>", "Notes", "Meeting notes attached below, thanks")
    return tmp_path


def test_evaluate_counts_and_lists_misses(tmp_path):
    ev = evaluate(build(tmp_path), cfg)
    assert sorted(r.label for r in ev.results) == ["legit", "legit", "phish", "phish"]
    out = render(ev, cfg)
    assert "2 phishing, 2 legitimate" in out
    assert "Phishing MISSED" in out and "p2.eml" in out and "p1.eml" not in out.split("Phishing MISSED")[1].split("Legit mail")[0]
    assert "WARNING: fewer than 30" in out
    assert "attachment.executable" in out and "Score sweep" in out

def test_unlabeled_and_duplicate_files(tmp_path):
    build(tmp_path)
    write(tmp_path / "other" / "x.eml", "A <a@example.org>", "s", "b")
    (tmp_path / "phish" / "p1-copy.eml").write_bytes((tmp_path / "phish" / "p1.eml").read_bytes())
    ev = evaluate(tmp_path, cfg)
    assert ev.unlabeled == 1 and ev.duplicates == 1 and len(ev.results) == 4

def test_labels_csv_overrides_folder(tmp_path):
    build(tmp_path)
    (tmp_path / "labels.csv").write_text("filename,label\np2.eml,legit\n")
    ev = evaluate(tmp_path, cfg)
    assert [r.label for r in ev.results if r.path.name == "p2.eml"] == ["legit"]

def test_dev_test_split_is_stable_and_partitions(tmp_path):
    build(tmp_path)
    a = {r.path.name for r in evaluate(tmp_path, cfg, only="dev").results}
    b = {r.path.name for r in evaluate(tmp_path, cfg, only="test").results}
    assert a.isdisjoint(b) and a | b == {"p1.eml", "p2.eml", "l1.eml", "l2.eml"}
    assert a == {r.path.name for r in evaluate(tmp_path, cfg, only="dev").results}

def test_cli_eval_runs(tmp_path):
    build(tmp_path)
    r = CliRunner().invoke(main, ["eval", str(tmp_path), "--details"])
    assert r.exit_code == 0 and "Detection by level" in r.output and "Every sample" in r.output

def test_cli_eval_without_labels_fails_cleanly(tmp_path):
    write(tmp_path / "x" / "a.eml", "A <a@example.org>", "s", "b")
    r = CliRunner().invoke(main, ["eval", str(tmp_path)])
    assert r.exit_code == 1


def test_wilson_range_is_honest_about_small_samples():
    lo, hi = wilson(0, 10)
    assert lo == 0.0 and 0.27 < hi < 0.29          # 0 of 10 still allows ~28%
    assert wilson(0, 100)[1] < 0.04                 # 100 samples: under 4%
    assert wilson(5, 5)[1] == 1.0 and wilson(0, 0) == (0.0, 1.0)

def test_level_table_shows_ranges(tmp_path):
    build(tmp_path)
    out = render(evaluate(tmp_path, cfg), cfg)
    assert "95% range" in out and "[0-" in out

def test_by_source_table_and_skip_dir(tmp_path):
    build(tmp_path)
    write(tmp_path / "legit" / "archive" / "old1.eml", "Sam <sam@example.org>", "old one", "hello old")
    write(tmp_path / "legit" / "archive" / "old2.eml", "Ann <ann@example.org>", "old two", "hello again")
    out = render(evaluate(tmp_path, cfg), cfg)
    assert "By source" in out and "legit/archive" in out and "phish" in out
    skipped = evaluate(tmp_path, cfg, skip_dirs={"Archive"})            # case-insensitive
    assert {r.source for r in skipped.results} == {"phish", "legit"}
    assert skipped.unlabeled == 0 and len(skipped.results) == 4

def test_cli_skip_dir(tmp_path):
    build(tmp_path)
    write(tmp_path / "legit" / "archive" / "old1.eml", "Sam <sam@example.org>", "old one", "hello old")
    r = CliRunner().invoke(main, ["eval", str(tmp_path), "--skip-dir", "archive"])
    assert r.exit_code == 0 and "2 phishing, 2 legitimate" in r.output


# ---------------------- Phase 1: manifest, groups, path overrides ---------------------- #

def test_manifest_keeps_campaign_group_together_and_records_provenance(tmp_path):
    build(tmp_path)
    (tmp_path / "manifest.csv").write_text(
        "path,group_id,dataset,license,reference,collection_date\n"
        "phish/p1.eml,phishing-pot:campaign-1,Phishing Pot,CC-BY-SA-4.0,https://example.org/source,2026-01-01\n"
        "phish/p2.eml,phishing-pot:campaign-1,Phishing Pot,CC-BY-SA-4.0,https://example.org/source,2026-01-01\n"
        "legit/l1.eml,legit-set:group-1,Modern mail,private,local,2026-01-01\n",
        encoding="utf-8",
    )
    all_results = evaluate(tmp_path, cfg).results
    by_group = {}
    for result in all_results:
        if result.group_id:
            by_group.setdefault(result.group_id, set()).add(result.split)
    assert by_group and all(len(splits) == 1 for splits in by_group.values())

    dev = {r.path.relative_to(tmp_path).as_posix() for r in evaluate(tmp_path, cfg, only="dev").results}
    test = {r.path.relative_to(tmp_path).as_posix() for r in evaluate(tmp_path, cfg, only="test").results}
    assert dev.isdisjoint(test)
    assert dev | test == {"phish/p1.eml", "phish/p2.eml", "legit/l1.eml", "legit/l2.eml"}
    assert all(len({r.split for r in all_results if r.group_id == group}) == 1 for group in by_group)
    p1 = next(r for r in all_results if r.path.name == "p1.eml")
    assert p1.dataset == "Phishing Pot" and p1.license == "CC-BY-SA-4.0"
    report = render(evaluate(tmp_path, cfg), cfg)
    assert "Campaign split:" in report and "Dataset metadata" in report


def test_manifest_invalid_path_fails_closed(tmp_path):
    build(tmp_path)
    (tmp_path / "manifest.csv").write_text("path,group_id\n../outside.eml,campaign-1\n", encoding="utf-8")
    ev = evaluate(tmp_path, cfg)
    assert ev.results == []
    assert ev.errors and "manifest.csv" in ev.errors[0]


def test_manifest_duplicate_path_fails_closed(tmp_path):
    build(tmp_path)
    (tmp_path / "manifest.csv").write_text(
        "path,group_id\nphish/p1.eml,campaign-1\nphish/p1.eml,campaign-2\n",
        encoding="utf-8",
    )
    ev = evaluate(tmp_path, cfg)
    assert ev.results == [] and "duplicate path" in ev.errors[0]


def test_manifest_unknown_path_fails_closed(tmp_path):
    build(tmp_path)
    (tmp_path / "manifest.csv").write_text(
        "path,group_id\nphish/not-present.eml,campaign-1\n", encoding="utf-8"
    )
    ev = evaluate(tmp_path, cfg)
    assert ev.results == [] and "not found" in ev.errors[0]


def test_manifest_entries_in_skipped_directory_are_allowed(tmp_path):
    build(tmp_path)
    write(tmp_path / "legit" / "archive" / "old.eml", "A <a@example.org>", "old", "old message")
    (tmp_path / "manifest.csv").write_text(
        "path,group_id\nlegit/archive/old.eml,archive-batch-1\n", encoding="utf-8"
    )
    ev = evaluate(tmp_path, cfg, skip_dirs={"archive"})
    assert len(ev.results) == 4 and not ev.errors


def test_labels_csv_relative_path_targets_only_one_file(tmp_path):
    build(tmp_path)
    write(tmp_path / "legit" / "p1.eml", "A <a@example.org>", "other", "ordinary message")
    (tmp_path / "labels.csv").write_text("path,label\nphish/p1.eml,legit\n", encoding="utf-8")
    ev = evaluate(tmp_path, cfg)
    labels = {r.path.relative_to(tmp_path).as_posix(): r.label for r in ev.results}
    assert labels["phish/p1.eml"] == "legit"
    assert labels["legit/p1.eml"] == "legit"


def test_labels_csv_unknown_path_is_ignored_with_warning(tmp_path):
    build(tmp_path)
    (tmp_path / "labels.csv").write_text(
        "path,label\nphish/missing.eml,legit\n", encoding="utf-8"
    )
    ev = evaluate(tmp_path, cfg)
    assert next(r for r in ev.results if r.path.name == "p1.eml").label == "phish"
    assert any("not found" in warning for warning in ev.warnings)


def test_ambiguous_filename_override_is_ignored_with_warning(tmp_path):
    write(tmp_path / "phish" / "same.eml", '"PayPal" <x@paypa1.example>', "verify", "http://1.2.3.4/login")
    write(tmp_path / "legit" / "same.eml", "Sam <sam@example.org>", "hello", "ordinary message")
    (tmp_path / "labels.csv").write_text("filename,label\nsame.eml,phish\n", encoding="utf-8")
    ev = evaluate(tmp_path, cfg)
    labels = {r.source: r.label for r in ev.results}
    assert labels["phish"] == "phish" and labels["legit"] == "legit"
    assert any("ambiguous" in warning for warning in ev.warnings)
    assert "ambiguous" in render(ev, cfg)
