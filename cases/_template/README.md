# Case NN: [short title]

| | |
|---|---|
| Data source | [dataset or lab, with link. Raw data is linked, never copied] |
| Data dates | [first and last event time in the data] |
| Platform | [SIEM or tool, version] |
| Tools | [Splunk, Sentinel, Wireshark, OSINT sites...] |
| ATT&CK | [technique IDs, e.g. T1190] |
| Hours | [time spent] |
| Status | [TODO] / In review / Done (date) |

## 1. Alert

[What started the investigation: the alert or the question, as a Tier 1 analyst would see it.]

## 2. Hypotheses

[What could explain the alert. Include the harmless explanation.]

## 3. Exhibits

[Searches and their results that prove each step. Searches are in `queries/`, screenshots in `exhibits/`.]

## 4. Timeline

| Time (UTC) | Host / IP | What happened | Exhibit |
|---|---|---|---|
| | | | |

## 5. Verdict

[True positive / false positive / benign true positive, and why. Scope: which hosts and accounts.]

## 6. Ticket

| Field | Value |
|---|---|
| Severity | |
| Summary | |
| Affected assets | |
| Actions taken / recommended | |
| Escalated to | |

## 7. Shift handover note

[Five lines or less: what is known, what is open, what the next shift should do first.]

## 8. Detection

[The rule this case produced. The rule file lives in `detections/`, with one search that should fire and one that should not.]

## 9. Takeaway

[What I learned.]

## 10. Hindsight

[What I would do differently, and what I checked too late.]

---
Indicators are defanged: `hxxp://`, `1.2.3[.]4`.
