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
