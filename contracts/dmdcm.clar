;; Decentralized Medical Data Consent Management

;; Data Maps
(define-map patient-consents 
    { patient: principal, provider: principal }
    { authorized: bool, timestamp: uint }
)

;; Public Functions
(define-public (grant-consent (provider principal))
    (begin
        (map-set patient-consents
            { patient: tx-sender, provider: provider }
            { authorized: true, timestamp: stacks-block-height }
        )
        (ok true)
    )
)

(define-public (revoke-consent (provider principal))
    (begin
        (map-set patient-consents
            { patient: tx-sender, provider: provider }
            { authorized: false, timestamp: stacks-block-height }
        )
        (ok true)
    )
)

;; Read Only Functions
(define-read-only (check-consent (patient principal) (provider principal))
    (default-to 
        { authorized: false, timestamp: u0 }
        (map-get? patient-consents { patient: patient, provider: provider })
    )
)



;; Patient Registry Contract

(define-map patients
    principal
    { name: (string-ascii 64), 
      dob: uint,
      registered: uint }
)

(define-public (register-patient (name (string-ascii 64)) (dob uint))
    (begin
        (map-set patients tx-sender
            { name: name, 
              dob: dob,
              registered: stacks-block-height }
        )
        (ok true)
    )
)

(define-read-only (get-patient-info (patient principal))
    (map-get? patients patient)
)



;; Provider Registry Contract

(define-map providers
    principal
    { name: (string-ascii 64), 
      license: (string-ascii 32),
      active: bool }
)

(define-public (register-provider (name (string-ascii 64)) (license (string-ascii 32)))
    (begin
        (map-set providers tx-sender
            { name: name, 
              license: license,
              active: true }
        )
        (ok true)
    )
)

(define-public (deactivate-provider)
    (begin
        (map-set providers tx-sender
            (merge (unwrap-panic (get-provider-info tx-sender))
                  { active: false })
        )
        (ok true)
    )
)

(define-read-only (get-provider-info (provider principal))
    (map-get? providers provider)
)




;; Access Log Contract

(define-map access-logs
    { patient: principal, provider: principal, timestamp: uint }
    { action: (string-ascii 20), details: (string-ascii 256) }
)

(define-data-var log-count uint u0)

(define-public (log-access (patient principal) (action (string-ascii 20)) (details (string-ascii 256)))
    (begin
        (map-set access-logs
            { patient: patient,
              provider: tx-sender,
              timestamp: stacks-block-height }
            { action: action,
              details: details }
        )
        (var-set log-count (+ (var-get log-count) u1))
        (ok true)
    )
)

(define-read-only (get-log-count)
    (var-get log-count)
)
