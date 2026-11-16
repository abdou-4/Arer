from email.message import EmailMessage

from arer.mail_parser import parse_mail_file


def _sample_eml(tmp_path):
    """Self-contained stand-in for data/samples/phish/phish_sample.eml.

    The real sample lives under /data/samples/*, which .gitignore excludes on
    purpose, so a test must not depend on it being present. This builds a
    synthetic mail with the same properties the assertions check for."""
    m = EmailMessage()
    m["From"] = "PayPal Security <security@paypa1.example>"
    m["To"] = "victim@corp.example"
    m["Subject"] = "Urgent: verify your account"
    m["Date"] = "Mon, 05 Jan 2026 09:00:00 +0000"
    m["Message-ID"] = "<alert-77@paypa1.example>"
    m.set_content("Please verify your account now.")
    m.add_alternative('<html><body>Secure login: '
                      '<a href="http://evil.example">http://paypa1.example/login</a>'
                      '</body></html>', subtype="html")
    m.add_attachment(b"%PDF-1.4\nfake\n", maintype="application", subtype="pdf", filename="inv.pdf")
    p = tmp_path / "phish_sample.eml"
    p.write_bytes(m.as_bytes())
    return p


def test_eml_core_fields(tmp_path):
    d = parse_mail_file(_sample_eml(tmp_path))
    assert d["file"]["format"] == "eml"
    assert d["envelope"]["subject"] == "Urgent: verify your account"
    assert d["envelope"]["from"][0]["domain"] == "paypa1.example"
    assert d["attachments"][0]["filename"] == "inv.pdf"
    assert d["indicators"]["href_text_mismatches"]
