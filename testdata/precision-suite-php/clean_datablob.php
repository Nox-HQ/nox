<?php
// Data-blob stressor: a long base64 data-URI embedded as a string literal. The
// long alphanumeric runs trip naive entropy/secret rules, but lexctx classifies
// the whole literal as a data blob, so nothing should fire. Zero findings.

$logo = 'data:image/svg+xml;base64,'
    . 'PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxMjgi'
    . 'IGhlaWdodD0iMTI4Ij48cmVjdCB3aWR0aD0iMTI4IiBoZWlnaHQ9IjEyOCIgZmlsbD0i'
    . 'IzAwN2FjYyIvPjx0ZXh0IHg9IjY0IiB5PSI3MCIgZm9udC1zaXplPSI0OCIgZmlsbD0i'
    . 'I2ZmZmIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIj5OPC90ZXh0Pjwvc3ZnPg==';

// A hex color palette and a UUID — identifiers, not secrets.
$brand = '#007acc';
$requestId = '550e8400-e29b-41d4-a716-446655440000';

echo strlen($logo);
