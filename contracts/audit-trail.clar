(define-constant ERR-UNAUTHORIZED u401)
(define-constant ERR-INVALID-PARAMS u400)
(define-constant ERR-NOT-FOUND u404)

(define-constant SEVERITY-INFO u1)
(define-constant SEVERITY-WARNING u2)
(define-constant SEVERITY-CRITICAL u3)

(define-map audit-events
    { event-id: uint }
    { 
        timestamp: uint,
        actor: principal,
        target-patient: (optional principal),
        target-provider: (optional principal),
        event-type: (string-ascii 32),
        severity: uint,
        details: (string-ascii 256),
        ip-hash: (optional (string-ascii 64)),
        session-id: (optional (string-ascii 32))
    })

(define-map audit-summary
    { date: uint }
    {
        total-events: uint,
        critical-events: uint,
        warning-events: uint,
        info-events: uint
    })

(define-map user-audit-count
    principal
    uint)

(define-data-var next-event-id uint u1)
(define-data-var total-audit-events uint u0)

(define-private (get-current-date)
    (/ stacks-block-height u144))

(define-public (log-audit-event
    (target-patient (optional principal))
    (target-provider (optional principal))
    (event-type (string-ascii 32))
    (severity uint)
    (details (string-ascii 256))
    (ip-hash (optional (string-ascii 64)))
    (session-id (optional (string-ascii 32))))
    (let ((event-id (var-get next-event-id))
          (current-date (get-current-date))
          (current-summary (default-to 
            { total-events: u0, critical-events: u0, warning-events: u0, info-events: u0 }
            (map-get? audit-summary { date: current-date })))
          (user-count (default-to u0 (map-get? user-audit-count tx-sender))))
        (map-set audit-events
            { event-id: event-id }
            {
                timestamp: stacks-block-height,
                actor: tx-sender,
                target-patient: target-patient,
                target-provider: target-provider,
                event-type: event-type,
                severity: severity,
                details: details,
                ip-hash: ip-hash,
                session-id: session-id
            })
        (map-set audit-summary
            { date: current-date }
            {
                total-events: (+ (get total-events current-summary) u1),
                critical-events: (+ (get critical-events current-summary) 
                    (if (is-eq severity SEVERITY-CRITICAL) u1 u0)),
                warning-events: (+ (get warning-events current-summary)
                    (if (is-eq severity SEVERITY-WARNING) u1 u0)),
                info-events: (+ (get info-events current-summary)
                    (if (is-eq severity SEVERITY-INFO) u1 u0))
            })
        (map-set user-audit-count tx-sender (+ user-count u1))
        (var-set next-event-id (+ event-id u1))
        (var-set total-audit-events (+ (var-get total-audit-events) u1))
        (ok event-id)))

(define-public (log-consent-granted (provider principal))
    (log-audit-event 
        (some tx-sender)
        (some provider)
        "CONSENT_GRANTED"
        SEVERITY-INFO
        "Patient granted consent to provider"
        none
        none))

(define-public (log-consent-revoked (provider principal))
    (log-audit-event
        (some tx-sender)
        (some provider)
        "CONSENT_REVOKED"
        SEVERITY-WARNING
        "Patient revoked consent from provider"
        none
        none))

(define-public (log-emergency-access (patient principal))
    (log-audit-event
        (some patient)
        (some tx-sender)
        "EMERGENCY_ACCESS"
        SEVERITY-CRITICAL
        "Emergency access activated"
        none
        none))

(define-public (log-data-access (patient principal) (data-type (string-ascii 32)))
    (log-audit-event
        (some patient)
        (some tx-sender)
        "DATA_ACCESS"
        SEVERITY-INFO
        data-type
        none
        none))

(define-public (log-unauthorized-attempt (target-patient principal))
    (log-audit-event
        (some target-patient)
        none
        "UNAUTHORIZED_ACCESS"
        SEVERITY-CRITICAL
        "Unauthorized access attempt detected"
        none
        none))

(define-read-only (get-audit-event (event-id uint))
    (map-get? audit-events { event-id: event-id }))

(define-read-only (get-daily-summary (date uint))
    (map-get? audit-summary { date: date }))

(define-read-only (get-user-activity-count (user principal))
    (default-to u0 (map-get? user-audit-count user)))

(define-read-only (get-total-events)
    (var-get total-audit-events))

(define-read-only (get-next-event-id)
    (var-get next-event-id))

(define-map compliance-reports
    { report-id: (string-ascii 32) }
    {
        generated-by: principal,
        start-date: uint,
        end-date: uint,
        total-events: uint,
        critical-count: uint,
        report-hash: (string-ascii 64),
        timestamp: uint
    })

(define-public (generate-compliance-report
    (report-id (string-ascii 32))
    (start-date uint)
    (end-date uint)
    (report-hash (string-ascii 64)))
    (let ((date-range (- end-date start-date)))
        (if (> date-range u365)
            (err ERR-INVALID-PARAMS)
            (begin
                (map-set compliance-reports
                    { report-id: report-id }
                    {
                        generated-by: tx-sender,
                        start-date: start-date,
                        end-date: end-date,
                        total-events: u0,
                        critical-count: u0,
                        report-hash: report-hash,
                        timestamp: stacks-block-height
                    })
                (ok true)))))

(define-read-only (get-compliance-report (report-id (string-ascii 32)))
    (map-get? compliance-reports { report-id: report-id }))

(define-map audit-filters
    { filter-id: (string-ascii 32) }
    {
        created-by: principal,
        event-types: (list 10 (string-ascii 32)),
        min-severity: uint,
        date-from: uint,
        date-to: uint
    })

(define-public (create-audit-filter
    (filter-id (string-ascii 32))
    (event-types (list 10 (string-ascii 32)))
    (min-severity uint)
    (date-from uint)
    (date-to uint))
    (begin
        (map-set audit-filters
            { filter-id: filter-id }
            {
                created-by: tx-sender,
                event-types: event-types,
                min-severity: min-severity,
                date-from: date-from,
                date-to: date-to
            })
        (ok true)))

(define-read-only (get-audit-filter (filter-id (string-ascii 32)))
    (map-get? audit-filters { filter-id: filter-id }))

(define-map retention-policies
    { policy-id: (string-ascii 32) }
    {
        retention-days: uint,
        auto-archive: bool,
        created-by: principal,
        applies-to: (list 5 (string-ascii 32))
    })

(define-public (set-retention-policy
    (policy-id (string-ascii 32))
    (retention-days uint)
    (auto-archive bool)
    (applies-to (list 5 (string-ascii 32))))
    (begin
        (map-set retention-policies
            { policy-id: policy-id }
            {
                retention-days: retention-days,
                auto-archive: auto-archive,
                created-by: tx-sender,
                applies-to: applies-to
            })
        (ok true)))

(define-read-only (get-retention-policy (policy-id (string-ascii 32)))
    (map-get? retention-policies { policy-id: policy-id }))

(define-map audit-alerts
    { alert-id: uint }
    {
        trigger-event: uint,
        alert-type: (string-ascii 32),
        severity: uint,
        message: (string-ascii 256),
        acknowledged: bool,
        created-at: uint
    })

(define-data-var next-alert-id uint u1)

(define-public (create-audit-alert
    (trigger-event uint)
    (alert-type (string-ascii 32))
    (severity uint)
    (message (string-ascii 256)))
    (let ((alert-id (var-get next-alert-id)))
        (map-set audit-alerts
            { alert-id: alert-id }
            {
                trigger-event: trigger-event,
                alert-type: alert-type,
                severity: severity,
                message: message,
                acknowledged: false,
                created-at: stacks-block-height
            })
        (var-set next-alert-id (+ alert-id u1))
        (ok alert-id)))

(define-public (acknowledge-alert (alert-id uint))
    (let ((alert (map-get? audit-alerts { alert-id: alert-id })))
        (if (is-some alert)
            (begin
                (map-set audit-alerts
                    { alert-id: alert-id }
                    (merge (unwrap-panic alert) { acknowledged: true }))
                (ok true))
            (err ERR-NOT-FOUND))))

(define-read-only (get-audit-alert (alert-id uint))
    (map-get? audit-alerts { alert-id: alert-id }))