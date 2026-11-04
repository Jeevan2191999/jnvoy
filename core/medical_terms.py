"""
Opt-in detection of medical terms: conditions, treatments and medicines. Entity type MEDICAL_TERM.

Off by default, because a condition or a medicine is not personal data until it is tied to a person, and hiding
every mention would make ordinary text unreadable. A customer switches it on with policy redact_extra
"medical_term" (or the server setting JNVOY_REDACT_EXTRA).

How it works, and what it cannot do. It is a word list plus three rules, not an understanding of medicine.

  1. Listed terms        conditions, treatments and medicines that are almost never used in another sense
                         ("diabetes", "chemotherapy", "metformin"). Matched ignoring case, as whole words.
  2. Cue-gated words     words with an everyday meaning ("cancer", "depression", "stroke") are hidden only
                         right after a clinical cue ("diagnosed with", "history of", "treated for").
  3. Medicine-name endings  words that end like a medicine ("-statin", "-pril", "-olol", "-mycin") are hidden, so
                         medicines that are not on the list have a chance. A dose after a word ("Ramipril 5 mg")
                         also marks that word.

What it misses: any condition or medicine that is not on the list, does not end like a medicine and has no
dose beside it (brand names such as "Prozac", for example), and everyday words used without a cue. The measured
share is on the accuracy page. What it hides wrongly is measured there too.
"""
import re
from typing import List

from presidio_analyzer import EntityRecognizer, RecognizerResult

ENTITY = "MEDICAL_TERM"

CONDITIONS = [
    "diabetes", "type 1 diabetes", "type 2 diabetes", "hypertension", "asthma", "epilepsy", "schizophrenia",
    "bipolar disorder", "hiv", "hepatitis", "leukaemia", "leukemia", "lymphoma", "melanoma", "copd",
    "arthritis", "rheumatoid arthritis", "osteoporosis", "migraine", "dementia", "alzheimer's disease",
    "alzheimer's", "parkinson's disease", "multiple sclerosis", "adhd", "ptsd", "anorexia nervosa", "bulimia",
    "eczema", "psoriasis", "crohn's disease", "ulcerative colitis", "coeliac disease", "celiac disease",
    "cystic fibrosis", "sickle cell anaemia", "hypothyroidism", "hyperthyroidism", "endometriosis",
    "polycystic ovary syndrome", "sleep apnoea", "sleep apnea", "tuberculosis", "pneumonia", "bronchitis",
    "covid-19", "long covid", "glaucoma", "cataracts", "chronic kidney disease", "heart failure",
    "coronary artery disease", "atrial fibrillation", "anaphylaxis",
]
PROCEDURES = [
    "chemotherapy", "radiotherapy", "dialysis", "mastectomy", "colonoscopy", "biopsy", "angioplasty",
    "bypass surgery", "cataract surgery", "knee replacement", "hip replacement", "ivf",
]
MEDICINES = [
    "metformin", "insulin", "ibuprofen", "paracetamol", "amoxicillin", "sertraline", "citalopram", "fluoxetine",
    "atorvastatin", "simvastatin", "omeprazole", "lansoprazole", "levothyroxine", "lisinopril", "amlodipine",
    "salbutamol", "warfarin", "apixaban", "prednisolone", "diazepam", "codeine", "morphine", "tramadol",
    "methotrexate", "gabapentin", "propranolol", "loratadine", "cetirizine",
]
# Everyday words: hidden only after a clinical cue.
AMBIGUOUS = [
    "cancer", "depression", "anxiety", "stroke", "flu", "infection", "injury", "fracture", "pregnancy",
    "obesity", "addiction", "heart attack", "heart disease", "kidney disease", "kidney failure", "liver disease",
    "high blood pressure", "panic attacks", "insomnia", "mental health condition",
]
CUES = [
    "diagnosed with", "diagnosis of", "suffers from", "suffering from", "suffered from", "history of",
    "treated for", "treatment for", "being treated for", "prescribed for", "symptoms of", "living with",
    "in remission from", "died of", "died from", "recovering from",
]
# How medicine names tend to end (the pharmaceutical naming stems).
STEMS = ["statin", "pril", "sartan", "olol", "prazole", "mycin", "cillin", "cycline", "azole", "ciclovir",
         "navir", "racetam", "apine", "pram", "azepam", "triptan", "gliptin", "gliflozin", "glutide",
         "lukast", "tidine", "xaban", "parin", "oxetine", "tinib", "platin"]
NOT_DRUG_WORDS = {
    "tablet", "tablets", "capsule", "capsules", "dose", "doses", "dosage", "daily", "take", "taking", "total",
    "about", "around", "approximately", "weighs", "weight", "strength", "contains", "containing", "extra",
    "another", "added", "only", "limit", "maximum", "minimum", "from", "than", "over", "under", "with",
}


def _alternation(terms: list) -> str:
    words = sorted({t.lower() for t in terms}, key=lambda t: (-len(t), t))
    return "|".join(r"[\s-]+".join(re.escape(w) for w in re.split(r"[\s-]+", t)) for t in words)


_WORD_START = r"(?<![\w'-])"
_WORD_END = r"(?![\w-])"
_LISTED = re.compile(_WORD_START + r"(?P<v>" + _alternation(CONDITIONS + PROCEDURES + MEDICINES) + r")" + _WORD_END,
                     re.IGNORECASE)
_CUED = re.compile(
    _WORD_START + r"(?:" + _alternation(CUES) + r")\s+(?:(?:a|an|the|severe|chronic|acute|early|late)\s+){0,2}"
    r"(?P<v>" + _alternation(AMBIGUOUS) + r")" + _WORD_END, re.IGNORECASE)
_STEMMED = re.compile(_WORD_START + r"(?P<v>[A-Za-z]{3,}(?:" + "|".join(STEMS) + r"))" + _WORD_END, re.IGNORECASE)
_DOSED = re.compile(_WORD_START + r"(?P<v>[A-Za-z]{4,})(?=\s+\d+(?:\.\d+)?\s?(?:mg|mcg|µg|ml)\b)", re.IGNORECASE)


class MedicalTermRecognizer(EntityRecognizer):
    def __init__(self):
        super().__init__(supported_entities=[ENTITY], supported_language="en", name="MedicalTermRecognizer")

    def load(self) -> None:  # noqa: D102
        pass

    def analyze(self, text: str, entities: List[str], nlp_artifacts=None) -> List[RecognizerResult]:
        if entities and ENTITY not in entities:
            return []
        out, seen = [], set()

        def add(m, score):
            span = (m.start("v"), m.end("v"))
            if span not in seen:
                seen.add(span)
                out.append(RecognizerResult(entity_type=ENTITY, start=span[0], end=span[1], score=score))

        for m in _LISTED.finditer(text):
            add(m, 0.85)
        for m in _CUED.finditer(text):
            add(m, 0.8)
        for m in _STEMMED.finditer(text):
            add(m, 0.7)
        for m in _DOSED.finditer(text):
            if m.group("v").lower() not in NOT_DRUG_WORDS:
                add(m, 0.7)
        return out
