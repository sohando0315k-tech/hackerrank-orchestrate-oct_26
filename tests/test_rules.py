"""Unit tests for deletion intent classification and policy engine."""

import pytest

from code.rules import (
    DeletionIntentClassifier,
    PolicyEngine,
    RequestIntent,
)


@pytest.fixture
def classifier():
    return DeletionIntentClassifier()


def test_explicit_deletion_english(classifier):
    """Verify standard explicit deletion requests in English."""
    t1 = "Please permanently delete the account associated with this email address."
    r1 = classifier.classify(t1)
    assert r1.intent == RequestIntent.DELETION
    assert r1.is_deletion_authorized
    assert r1.detected_language == "English"

    t2 = "I want to close this account and have its associated personal data deleted."
    r2 = classifier.classify(t2)
    assert r2.intent == RequestIntent.DELETION
    assert r2.is_deletion_authorized

    t3 = "Please erase my profile and all data."
    r3 = classifier.classify(t3)
    assert r3.intent == RequestIntent.DELETION
    assert r3.is_deletion_authorized


def test_access_request_without_deletion(classifier):
    """Verify access / copy requests without deletion are classified as ACCESS."""
    t1 = "Can you tell me what personal information you hold about me? This is an information request, not a request to erase it."
    r1 = classifier.classify(t1)
    assert r1.intent == RequestIntent.ACCESS
    assert not r1.is_deletion_authorized

    t2 = "I need a copy of last year's invoices for my records. Please leave my profile and purchase history in place."
    r2 = classifier.classify(t2)
    assert r2.intent == RequestIntent.ACCESS
    assert not r2.is_deletion_authorized

    t3 = "Could you send me a copy of the information held on my account? I still use it, so please don't delete or change anything."
    r3 = classifier.classify(t3)
    assert r3.intent == RequestIntent.ACCESS
    assert not r3.is_deletion_authorized


def test_rectification_request_without_deletion(classifier):
    """Verify rectification / data correction requests are classified as RECTIFICATION."""
    t1 = "My surname is misspelled on the account. Can you correct it without removing any of my records?"
    r1 = classifier.classify(t1)
    assert r1.intent == RequestIntent.RECTIFICATION
    assert not r1.is_deletion_authorized

    t2 = "The mobile number on my profile is out of date. Please replace it with the new one and leave the account active."
    r2 = classifier.classify(t2)
    assert r2.intent == RequestIntent.RECTIFICATION
    assert not r2.is_deletion_authorized

    t3 = "Please change the email address used for this account. I want to continue using the service."
    r3 = classifier.classify(t3)
    assert r3.intent == RequestIntent.RECTIFICATION
    assert not r3.is_deletion_authorized


def test_portability_request_without_deletion(classifier):
    """Verify data portability export requests are classified as PORTABILITY."""
    t = "I'd like to download my account information in a portable format. Please keep the account as it is."
    r = classifier.classify(t)
    assert r.intent == RequestIntent.PORTABILITY
    assert not r.is_deletion_authorized


def test_marketing_optout_without_deletion(classifier):
    """Verify marketing opt-out requests are classified as MARKETING_OPTOUT."""
    t1 = "Please stop the promotional emails. I still need the account and my order history, so I am not asking for deletion."
    r1 = classifier.classify(t1)
    assert r1.intent == RequestIntent.MARKETING_OPTOUT
    assert not r1.is_deletion_authorized

    t2 = "Please remove me from marketing lists only. I still want receipts and service messages for this account."
    r2 = classifier.classify(t2)
    assert r2.intent == RequestIntent.MARKETING_OPTOUT
    assert not r2.is_deletion_authorized


def test_account_recovery_without_deletion(classifier):
    """Verify account / password recovery requests are classified as ACCOUNT_RECOVERY."""
    t = "I can't access my profile and need help resetting the login. Do not close the account."
    r = classifier.classify(t)
    assert r.intent == RequestIntent.ACCOUNT_RECOVERY
    assert not r.is_deletion_authorized


def test_mixed_intent_with_deletion(classifier):
    """Verify mixed requests requesting download/support AND deletion authorize deletion."""
    t1 = "Please delete my account and the identity document I sent to support while resolving a delivery issue."
    r1 = classifier.classify(t1)
    assert r1.intent == RequestIntent.DELETION
    assert r1.is_deletion_authorized

    t2 = "I closed my account, but an old 'download your data' link still works. Please delete that export file as well."
    r2 = classifier.classify(t2)
    assert r2.intent == RequestIntent.DELETION
    assert r2.is_deletion_authorized


def test_negated_deletion_language(classifier):
    """Verify negation overrides deletion keywords."""
    t = "Do not delete my account, I just want to update my email address."
    r = classifier.classify(t)
    assert not r.is_deletion_authorized
    assert r.intent in (RequestIntent.RECTIFICATION, RequestIntent.AMBIGUOUS)


def test_multilingual_deletion_requests(classifier):
    """Verify representative non-English deletion requests across supported languages."""
    # Spanish
    es_txt = "Solicito la eliminación permanente de la cuenta asociada a este correo. Revisen los identificadores actuales y anteriores."
    res_es = classifier.classify(es_txt)
    assert res_es.intent == RequestIntent.DELETION
    assert res_es.is_deletion_authorized
    assert res_es.detected_language == "Spanish"

    # Portuguese
    pt_txt = "Solicito a exclusão permanente da conta associada a este e-mail. Verifiquem os identificadores atuais e anteriores."
    res_pt = classifier.classify(pt_txt)
    assert res_pt.intent == RequestIntent.DELETION
    assert res_pt.is_deletion_authorized
    assert res_pt.detected_language == "Portuguese"

    # French
    fr_txt = "Je demande la suppression définitive du compte associé à cette adresse e-mail. Veuillez examiner les identifiants."
    res_fr = classifier.classify(fr_txt)
    assert res_fr.intent == RequestIntent.DELETION
    assert res_fr.is_deletion_authorized
    assert res_fr.detected_language == "French"

    # German
    de_txt = "Bitte löschen Sie das mit dieser Adresse verknüpfte Konto dauerhaft. Bitte bestätigen Sie das Ergebnis."
    res_de = classifier.classify(de_txt)
    assert res_de.intent == RequestIntent.DELETION
    assert res_de.is_deletion_authorized
    assert res_de.detected_language == "German"

    # Italian
    it_txt = "Desidero cancellare definitivamente l'account collegato a questa email. Grazie per la conferma."
    res_it = classifier.classify(it_txt)
    assert res_it.intent == RequestIntent.DELETION
    assert res_it.is_deletion_authorized

    # Korean
    ko_txt = "이 이메일 주소와 연결된 계정을 영구적으로 삭제해 주시기 바랍니다."
    res_ko = classifier.classify(ko_txt)
    assert res_ko.intent == RequestIntent.DELETION
    assert res_ko.is_deletion_authorized
    assert res_ko.detected_language == "Korean"

    # Japanese
    ja_txt = "このメールアドレスに関連付けられているアカウントの完全な削除をお願いします。"
    res_ja = classifier.classify(ja_txt)
    assert res_ja.intent == RequestIntent.DELETION
    assert res_ja.is_deletion_authorized
    assert res_ja.detected_language == "Japanese"


def test_ambiguous_text(classifier):
    """Verify ambiguous or empty text is classified safely as AMBIGUOUS."""
    r_empty = classifier.classify("")
    assert r_empty.intent == RequestIntent.AMBIGUOUS
    assert not r_empty.is_deletion_authorized

    r_none = classifier.classify(None)
    assert r_none.intent == RequestIntent.AMBIGUOUS
    assert not r_none.is_deletion_authorized

    r_gibberish = classifier.classify("Hello, thanks for the great service yesterday!")
    assert r_gibberish.intent == RequestIntent.AMBIGUOUS
    assert not r_gibberish.is_deletion_authorized


def test_policy_engine_integration():
    """Verify PolicyEngine delegates to classifier properly."""
    engine = PolicyEngine()
    assert engine.is_deletion_authorized("Please delete my account.")
    assert not engine.is_deletion_authorized("The mobile number is out of date. Leave the account active.")

    intent_res = engine.classify_intent("Please delete my account.")
    assert intent_res.intent == RequestIntent.DELETION
    assert intent_res.is_deletion_authorized


def test_refusal_and_non_adjacent_negation(classifier):
    """Verify that explicit refusal of deletion (including non-adjacent phrasing) is NEVER authorized."""
    # Non-adjacent negation: "do not want ... deleted"
    r1 = classifier.classify("I do not want my account deleted.")
    assert not r1.is_deletion_authorized
    assert r1.intent == RequestIntent.AMBIGUOUS

    # Contracted and unpunctuated: "dont want ... erased"
    r2 = classifier.classify("I dont want my data erased.")
    assert not r2.is_deletion_authorized
    assert r2.intent == RequestIntent.AMBIGUOUS

    # Explicit statement: not asking for deletion
    r3 = classifier.classify("I am contacting you regarding account options; note that I am not asking for deletion.")
    assert not r3.is_deletion_authorized
    assert r3.intent == RequestIntent.AMBIGUOUS

    # Instruction to leave active
    r4 = classifier.classify("Please leave my profile active and do not remove anything.")
    assert not r4.is_deletion_authorized
    assert r4.intent == RequestIntent.AMBIGUOUS

    # Multilingual refusals
    r_es = classifier.classify("No quiero la eliminación de mi cuenta.")
    assert not r_es.is_deletion_authorized
    r_de = classifier.classify("Bitte mein Konto aktiv lassen und nicht löschen.")
    assert not r_de.is_deletion_authorized
    r_fr = classifier.classify("Ne supprimez pas mon compte s'il vous plaît.")
    assert not r_fr.is_deletion_authorized


def test_scoped_retention_preserves_deletion(classifier):
    """Verify that scoped retention clauses (e.g. tax records) preserve affirmative deletion."""
    # Deletion first, then retention exception
    t1 = "Please delete my profile, but retain tax records."
    r1 = classifier.classify(t1)
    assert r1.intent == RequestIntent.DELETION
    assert r1.is_deletion_authorized
    assert "tax records" in r1.retention_exceptions

    # Retention first, then affirmative deletion
    t2 = "Do not delete my tax records, but delete my profile."
    r2 = classifier.classify(t2)
    assert r2.intent == RequestIntent.DELETION
    assert r2.is_deletion_authorized
    assert "tax records" in r2.retention_exceptions

    # Erase data except invoices
    t3 = "Please erase all my personal data with the exception of billing invoices for auditing."
    r3 = classifier.classify(t3)
    assert r3.intent == RequestIntent.DELETION
    assert r3.is_deletion_authorized
    assert any("invoices" in ret for ret in r3.retention_exceptions)


def test_historical_context_mentions(classifier):
    """Verify that historical past-tense references to deletion do not authorize new deletions."""
    # Passive past: "was deleted last year"
    t1 = "My account was deleted last year."
    r1 = classifier.classify(t1)
    assert not r1.is_deletion_authorized
    assert r1.intent == RequestIntent.AMBIGUOUS

    # Past event combined with account recovery
    t2 = "My old account was deleted; help me create a new one."
    r2 = classifier.classify(t2)
    assert not r2.is_deletion_authorized
    assert r2.intent == RequestIntent.ACCOUNT_RECOVERY

    # Observation of past closure
    t3 = "The previous profile had been deleted already by customer support."
    r3 = classifier.classify(t3)
    assert not r3.is_deletion_authorized


def test_multilingual_conjugations_and_transliterations(classifier):
    """Verify that common Romance subjunctive/imperative forms and transliterated German authorize deletion."""
    # Spanish subjunctive / polite imperative: "elimine"
    r_es = classifier.classify("Por favor elimine mi cuenta y todos mis datos personales.")
    assert r_es.intent == RequestIntent.DELETION
    assert r_es.is_deletion_authorized
    assert r_es.detected_language == "Spanish"

    # Portuguese subjunctive / polite imperative: "exclua"
    r_pt = classifier.classify("Por favor, exclua minha conta e todos os dados associados.")
    assert r_pt.intent == RequestIntent.DELETION
    assert r_pt.is_deletion_authorized
    assert r_pt.detected_language == "Portuguese"

    # German transliteration: "loeschen" (without umlaut)
    r_de = classifier.classify("Bitte loeschen Sie mein Konto und alle personenbezogenen Daten.")
    assert r_de.intent == RequestIntent.DELETION
    assert r_de.is_deletion_authorized
    assert r_de.detected_language == "German"

    # Dutch deletion
    r_nl = classifier.classify("Gelieve mijn account en alle gegevens te verwijderen.")
    assert r_nl.intent == RequestIntent.DELETION
    assert r_nl.is_deletion_authorized
    assert r_nl.detected_language == "Dutch"

# -----------------------------------------------------------------------------
# Sprint 3C Tests: Deletion Audit and Verification Intent
# -----------------------------------------------------------------------------

def test_deletion_audit_and_confirmation_requests() -> None:
    """Verify that requests asking to verify, audit, or confirm past deletion authorize deletion auditing."""
    classifier = DeletionIntentClassifier()

    cases = [
        "Could you verify that the profile is gone and that anything related to it has been dealt with?",
        "Please check the latest state and confirm that the profile is gone.",
        "Can you verify that my account was deleted? A search result with a similar email belongs to someone else.",
        "I was told the account had been deleted, but I can still find traces in search, support, and analytics. Please handle them and disable any synchronization that could recreate them.",
        "Please audit the deletion as it stood when my request was reviewed. I want confirmation that the account was fully removed.",
        "The privacy page still says my request failed. Please inspect the actual systems and tell me whether the account and identity records are truly gone.",
    ]
    for prompt in cases:
        res = classifier.classify(prompt)
        assert res.is_deletion_authorized is True, f"Failed on prompt: {prompt}"
        assert res.intent == RequestIntent.DELETION, f"Expected DELETION intent for prompt: {prompt}"


def test_deletion_audit_negation_takes_precedence() -> None:
    """Explicit refusal or negation must override audit requests."""
    classifier = DeletionIntentClassifier()
    prompt = "Please verify my account, but do not delete my profile or remove any records."
    res = classifier.classify(prompt)
    assert res.is_deletion_authorized is False


def test_historical_mention_without_audit_instructions_remains_non_deletion() -> None:
    """Pure historical observation without deletion audit instructions remains non-deletion."""
    classifier = DeletionIntentClassifier()

    r1 = classifier.classify("My account was deleted last year. Can you send me a copy of my old invoices?")
    assert r1.is_deletion_authorized is False
    assert r1.intent == RequestIntent.ACCESS

    r2 = classifier.classify("My account was deleted last month. Can you help me reset my password?")
    assert r2.is_deletion_authorized is False
    assert r2.intent == RequestIntent.ACCOUNT_RECOVERY
