# Codebase Map

This document summarizes the public `baekho-phishing-analyzer` repository.
It intentionally describes only the code, tests, and docs included in this
public export.

## Overview

Baekho is a FastAPI-based phishing analysis MVP. It serves public static pages
for `baekho.app` and provides rule-based analysis for suspicious URLs and
`.eml` email uploads.

## Top-Level Files

- `README.md`: public repository overview and scope
- `requirements.txt`: runtime dependencies
- `Dockerfile`: container image definition for the FastAPI app
- `app/`: application code and public static assets
- `tests/`: public-safe unit tests
- `docs/`: public project notes

## Application Structure

- `app/main.py`: creates the FastAPI application, mounts static assets, applies
  no-cache headers for public pages, and includes routers.
- `app/routes/site.py`: serves public pages such as `/`, `/demo`, `/report`,
  `/team`, `/updates`, and `/contact`.
- `app/routes/analysis.py`: exposes `/analyze/url` and `/analyze/eml`, applies
  request guards, validates uploads, records audit events, and returns typed
  response models.
- `app/schemas.py`: Pydantic response models for URL and EML analysis outputs.
- `app/ops_guard.py`: upload size limits, rate-limit settings, client
  fingerprinting, and local audit log handling.
- `app/services/`: response builders that convert analyzer results into API
  payloads.
- `app/analyzers/`: rule-based detection logic for headers, body content, URLs,
  attachments, URL probing, risk fusion, and explainable reports.
- `app/static/`: public site pages and browser assets.

## Analysis Flow

### URL Analysis

1. `POST /analyze/url` receives a URL.
2. `app/analyzers/url_scoring.py` normalizes and scores static URL signals.
3. URL probing can add browser/crawler-derived signals when enabled.
4. `app/services/analysis_response.py` wraps the result with an explainable
   report and final severity.

### EML Analysis

1. `POST /analyze/eml` receives a `.eml` upload.
2. `app/analyzers/pipeline.py` parses the email with the standard library email
   parser.
3. Header, body, URL, and attachment analyzers produce component scores and
   evidence.
4. `app/analyzers/risk_fusion.py` combines component scores.
5. `app/analyzers/explainable_report.py` produces user-readable evidence and
   recommended actions.

## Public Scope

This repository excludes private operational material, real submitted samples,
runtime logs, deployment runbooks, internal datasets, and private conversation
records. Public documentation and tests should use synthetic examples only.

## Test Scope

The public test suite is intended to run from this repository without private
fixtures. When adding tests, use synthetic emails, `.example` domains, and
documentation-reserved IP ranges.
