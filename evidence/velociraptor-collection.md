# Velociraptor collection validation

## Objective

Prove a benign remote collection path from the DFIR role to the designated Windows endpoint.

## Result

**PASS at deployment time**

- The endpoint agent enrolled with the DFIR-hosted server.
- An administrative API identity was created with an explicit role.
- A benign client-information artifact was collected remotely.
- Returned metadata was checked against the intended Windows target.
- The result established transport, enrollment, authorization, execution, and response retrieval.

## Current-state caveat

This is historical deployment evidence. A fresh service, listener, and client preflight is required before relying on the collection path in a new exercise.

## Sanitization

Client IDs, addresses, ports, API credentials, server configuration, collection IDs, and returned host metadata are omitted.
