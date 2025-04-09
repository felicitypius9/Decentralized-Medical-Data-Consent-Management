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



;; Emergency contacts map
(define-map emergency-contacts
    principal  ;; patient
    (list 3 principal)) ;; up to 3 emergency contacts

;; Emergency override status
(define-map emergency-override
    { patient: principal, provider: principal }
    { active: bool, activated-by: principal, timestamp: uint })

(define-public (add-emergency-contact (contact principal))
    (let ((current-contacts (default-to (list) (map-get? emergency-contacts tx-sender))))
        (if (< (len current-contacts) u3)
            (begin
                (map-set emergency-contacts 
                    tx-sender 
                    (unwrap-panic (as-max-len? (concat current-contacts (list contact)) u3)))
                (ok true))
            (err u403))))
            
(define-read-only (is-contact (contact principal) (patient principal))
    (let ((contacts (default-to (list) (map-get? emergency-contacts patient))))
        (is-some (index-of contacts contact))))

(define-public (activate-emergency-access (patient principal))
    (let ((is-emergency-contact (is-contact tx-sender patient)))
        (if is-emergency-contact
            (begin
                (map-set emergency-override 
                    { patient: patient, provider: tx-sender }
                    { active: true, activated-by: tx-sender, timestamp: stacks-block-height })
                (ok true))
            (err u403))))


(define-map timed-consents
    { patient: principal, provider: principal }
    { expiry: uint, authorized: bool })

(define-public (grant-timed-consent (provider principal) (duration uint))
    (let ((expiry (+ stacks-block-height duration)))
        (map-set timed-consents
            { patient: tx-sender, provider: provider }
            { expiry: expiry, authorized: true })
        (ok true)))

(define-read-only (check-timed-consent (patient principal) (provider principal))
    (let ((consent (map-get? timed-consents { patient: patient, provider: provider })))
        (match consent
            c (< stacks-block-height (get expiry c))
            false)))



(define-map category-permissions
    { patient: principal, provider: principal, category: (string-ascii 20) }
    { authorized: bool })

(define-public (set-category-permission (provider principal) (category (string-ascii 20)) (authorized bool))
    (begin
        (map-set category-permissions
            { patient: tx-sender, provider: provider, category: category }
            { authorized: authorized })
        (ok true)))

(define-read-only (check-category-permission (patient principal) (provider principal) (category (string-ascii 20)))
    (default-to 
        { authorized: false }
        (map-get? category-permissions { patient: patient, provider: provider, category: category })))



(define-map sharing-history
    principal  ;; patient
    (list 51 { provider: principal, timestamp: uint, action: (string-ascii 20) }))

(define-public (record-sharing (patient principal) (action (string-ascii 20)))
    (let ((current-history (default-to (list) (map-get? sharing-history patient))))
        (map-set sharing-history 
            patient
            (unwrap-panic (as-max-len? (append current-history { provider: tx-sender, 
                                    timestamp: stacks-block-height, 
                                    action: action }) u51)))
        (ok true)))



(define-map provider-ratings
    principal  ;; provider
    { total-score: uint, count: uint })

(define-public (rate-provider (provider principal) (score uint))
    (let ((current-rating (default-to { total-score: u0, count: u0 } 
                          (map-get? provider-ratings provider))))
        (map-set provider-ratings 
            provider
            { total-score: (+ (get total-score current-rating) score),
              count: (+ (get count current-rating) u1) })
        (ok true)))



(define-map consent-groups
    { group-id: (string-ascii 32) }
    (list 50 principal))  ;; list of providers

(define-public (create-consent-group (group-id (string-ascii 32)) (provider-list (list 50 principal)))
    (begin
        (map-set consent-groups
            { group-id: group-id }
            provider-list)
        (ok true)))

(define-public (grant-group-consent (group-id (string-ascii 32)))
    (let ((group-providers (default-to (list) (map-get? consent-groups { group-id: group-id }))))
        (map grant-consent group-providers)
        (ok true)))


(define-map access-requests
    { patient: principal, provider: principal }
    { status: (string-ascii 10), timestamp: uint, purpose: (string-ascii 256) })

(define-public (request-access (patient principal) (purpose (string-ascii 256)))
    (begin
        (map-set access-requests
            { patient: patient, provider: tx-sender }
            { status: "pending", timestamp: stacks-block-height, purpose: purpose })
        (ok true)))

(define-public (respond-to-request (provider principal) (approved bool))
    (begin
        (map-set access-requests
            { patient: tx-sender, provider: provider }
            { status: (if approved "approved" "denied"),
              timestamp: stacks-block-height,
              purpose: (get purpose (default-to { purpose: "" } 
                      (map-get? access-requests { patient: tx-sender, provider: provider }))) })
        (if approved
            (grant-consent provider)
            (ok true))))


;; Data export tracking
(define-map data-exports 
    { patient: principal, timestamp: uint }
    { format: (string-ascii 10), data-hash: (string-ascii 64) })

(define-public (record-data-export (format (string-ascii 10)) (data-hash (string-ascii 64)))
    (begin
        (map-set data-exports
            { patient: tx-sender, timestamp: stacks-block-height }
            { format: format, data-hash: data-hash })
        (ok true)))


(define-map delegated-consents
    { patient: principal, delegate: principal }
    { active: bool, expiry: uint })

(define-public (delegate-consent-management (delegate principal) (duration uint))
    (begin
        (map-set delegated-consents
            { patient: tx-sender, delegate: delegate }
            { active: true, expiry: (+ stacks-block-height duration) })
        (ok true)))

(define-read-only (check-delegation (patient principal) (delegate principal))
    (let ((delegation (default-to { active: false, expiry: u0 } 
                      (map-get? delegated-consents { patient: patient, delegate: delegate }))))
        (and (get active delegation)
             (> (get expiry delegation) stacks-block-height))))



(define-map provider-specializations
    principal
    (list 5 (string-ascii 32)))

(define-public (add-specialization (specialization (string-ascii 32)))
    (let ((current-specs (default-to (list) (map-get? provider-specializations tx-sender))))
        (map-set provider-specializations
            tx-sender
            (unwrap-panic (as-max-len? (append current-specs specialization) u5)))
        (ok true)))


(define-map patient-data-categories
    principal
    (list 10 { category: (string-ascii 32), last-updated: uint }))

(define-public (add-data-category (category (string-ascii 32)))
    (let ((current-categories (default-to (list) (map-get? patient-data-categories tx-sender))))
        (map-set patient-data-categories
            tx-sender
            (unwrap-panic (as-max-len? 
                (append current-categories { category: category, last-updated: stacks-block-height }) 
                u10)))
        (ok true)))



(define-map access-time-restrictions
    { patient: principal, provider: principal }
    { start-time: uint, end-time: uint })

(define-public (set-access-time (provider principal) (start-time uint) (end-time uint))
    (begin
        (map-set access-time-restrictions
            { patient: tx-sender, provider: provider }
            { start-time: start-time, end-time: end-time })
        (ok true)))


(define-map consent-templates
    (string-ascii 32)
    { description: (string-ascii 256), duration: uint, categories: (list 5 (string-ascii 32)) })

(define-public (create-consent-template 
    (template-id (string-ascii 32))
    (description (string-ascii 256))
    (duration uint)
    (categories (list 5 (string-ascii 32))))
    (begin
        (map-set consent-templates
            template-id
            { description: description, duration: duration, categories: categories })
        (ok true)))


(define-map patient-notes
    { patient: principal, timestamp: uint }
    { note: (string-ascii 256), provider: principal })

(define-public (add-patient-note (patient principal) (note (string-ascii 256)))
    (begin
        (map-set patient-notes
            { patient: patient, timestamp: stacks-block-height }
            { note: note, provider: tx-sender })
        (ok true)))


(define-map access-levels
    { patient: principal, provider: principal }
    { level: uint, description: (string-ascii 64) })

(define-public (set-access-level 
    (provider principal) 
    (level uint) 
    (description (string-ascii 64)))
    (begin
        (map-set access-levels
            { patient: tx-sender, provider: provider }
            { level: level, description: description })
        (ok true)))



(define-map batch-consent-operations
    { batch-id: (string-ascii 32) }
    { providers: (list 50 principal), status: (string-ascii 10) })

(define-public (batch-grant-consent (batch-id (string-ascii 32)) (provider-list (list 50 principal)))
    (begin
        (map-set batch-consent-operations
            { batch-id: batch-id }
            { providers: provider-list, status: "granted" })
        (map grant-consent provider-list)
        (ok true)))

(define-public (batch-revoke-consent (batch-id (string-ascii 32)) (provider-list (list 50 principal)))
    (begin
        (map-set batch-consent-operations
            { batch-id: batch-id }
            { providers: provider-list, status: "revoked" })
        (map revoke-consent provider-list)
        (ok true)))

(define-read-only (get-batch-operation (batch-id (string-ascii 32)))
    (map-get? batch-consent-operations { batch-id: batch-id }))




(define-map consent-timeline
    { patient: principal }
    (list 100 { 
        timestamp: uint,
        provider: principal,
        action: (string-ascii 20),
        details: (string-ascii 256)
    }))

(define-public (record-consent-action 
    (provider principal) 
    (action (string-ascii 20)) 
    (details (string-ascii 256)))
    (let ((current-timeline (default-to (list) 
            (map-get? consent-timeline { patient: tx-sender }))))
        (map-set consent-timeline
            { patient: tx-sender }
            (unwrap-panic (as-max-len? 
                (append current-timeline {
                    timestamp: stacks-block-height,
                    provider: provider,
                    action: action,
                    details: details
                }) u100)))
        (ok true)))

(define-read-only (get-consent-timeline (patient principal))
    (default-to (list) (map-get? consent-timeline { patient: patient })))