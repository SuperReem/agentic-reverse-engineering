from typing import Annotated, Literal
from pydantic import BaseModel, Field, field_validator


class Evidence(BaseModel):
    source: Literal[
        "static",
        "dynamic",
        "experiment",
    ]

    description: str


class TestCase(BaseModel):
    arguments: list[Annotated[str, Field(max_length=4096)]] = Field(default_factory=list, max_length=32)

    @field_validator("arguments")
    @classmethod
    def reject_null_bytes(cls, arguments):
        if any("\0" in argument for argument in arguments):
            raise ValueError("Command-line arguments cannot contain NUL bytes")
        return arguments

    reason: str = Field(min_length=1, max_length=2000)


class DynamicTestPlan(BaseModel):
    tests: list[TestCase] = Field(
        min_length=1,
        max_length=10,
    )


class AnalysisResult(BaseModel):
    target: str

    hypothesis: str

    proposed_name: str | None = None

    evidence: list[Evidence] = Field(default_factory=list)

    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )

    limitations: list[str] = Field(default_factory=list)


class ExperimentRequest(BaseModel):
    description: str
    reason: str


class FunctionSummary(BaseModel):
    purpose: str = Field(description="One short sentence describing the supported function purpose.")
    inputs: str = Field(description="Brief input description; say unknown when evidence is insufficient.")
    behavior: str = Field(description="Brief description of the key operation supported by evidence.")
    outputs: str = Field(description="Brief return value or side-effect description; say unknown if unestablished.")


class Verdict(BaseModel):
    status: Literal[
        "verified",
        "rejected",
        "uncertain",
    ]

    conclusion: str

    summary: FunctionSummary | None = Field(
        default=None,
        description="Structured function assessment. Populate for every new verdict, including uncertain or rejected decisions.",
    )

    unresolved_points: list[str] = Field(
        default_factory=list,
        max_length=3,
        description="Up to three short, material uncertainties or limitations remaining after review.",
    )

    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )

    reasoning: str

    supporting_evidence: list[str] = Field(default_factory=list)

    contradictions: list[str] = Field(default_factory=list)

    needs_more_evidence: bool = False

    experiment: ExperimentRequest | None = None
