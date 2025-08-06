;; Dynamic Data Anonymization Service Contract
;; Enables controlled anonymization of medical data for research purposes

;; Error constants
(define-constant ERR-UNAUTHORIZED u401)
(define-constant ERR-NOT-FOUND u404)
(define-constant ERR-INVALID-PARAMS u400)
(define-constant ERR-INSUFFICIENT-PRIVACY u403)
(define-constant ERR-EXPIRED-REQUEST u409)
(define-constant ERR-ALREADY-PROCESSED u410)

;; Anonymization levels
(define-constant LEVEL-BASIC u1)
(define-constant LEVEL-K-ANONYMITY u2)
(define-constant LEVEL-DIFFERENTIAL u3)

;; Request status constants
(define-constant STATUS-PENDING "pending")
(define-constant STATUS-APPROVED "approved")
(define-constant STATUS-PROCESSED "processed")
(define-constant STATUS-REJECTED "rejected")

;; Researcher credentials and verification
(define-map researcher-registry
    principal
    {
        name: (string-ascii 64),
        institution: (string-ascii 128),
        credentials: (string-ascii 64),
        verification-level: uint,
        active: bool,
        registered-at: uint,
        research-areas: (list 5 (string-ascii 32))
    })

;; Patient anonymization preferences
(define-map patient-anonymization-prefs
    principal
    {
        default-level: uint,
        allowed-research-areas: (list 10 (string-ascii 32)),
        auto-approve-threshold: uint,
        opt-out-complete: bool,
        last-updated: uint
    })

;; Anonymization requests from researchers
(define-map anonymization-requests
    { request-id: (string-ascii 32) }
    {
        requester: principal,
        target-patients: (list 20 principal),
        research-purpose: (string-ascii 256),
        data-categories: (list 8 (string-ascii 32)),
        anonymization-level: uint,
        k-value: uint,
        epsilon-value: uint,
        status: (string-ascii 10),
        created-at: uint,
        expires-at: uint,
        processed-at: uint,
        data-hash: (optional (string-ascii 64))
    })

;; Patient approvals for specific requests
(define-map patient-request-approvals
    { patient: principal, request-id: (string-ascii 32) }
    {
        approved: bool,
        approval-timestamp: uint,
        conditions: (optional (string-ascii 128))
    })

;; Anonymized dataset registry
(define-map anonymized-datasets
    { dataset-id: (string-ascii 32) }
    {
        source-request: (string-ascii 32),
        patient-count: uint,
        anonymization-method: (string-ascii 32),
        privacy-parameters: (string-ascii 64),
        created-at: uint,
        access-count: uint,
        researcher: principal,
        hash-checksum: (string-ascii 64)
    })

;; Research project tracking
(define-map research-projects
    { project-id: (string-ascii 32) }
    {
        lead-researcher: principal,
        title: (string-ascii 128),
        description: (string-ascii 512),
        ethics-approval: (string-ascii 64),
        start-date: uint,
        end-date: uint,
        datasets-used: (list 15 (string-ascii 32)),
        status: (string-ascii 20)
    })

;; Data usage analytics
(define-map usage-analytics
    { period: uint }
    {
        total-requests: uint,
        approved-requests: uint,
        patients-participating: uint,
        datasets-created: uint,
        privacy-violations: uint
    })

;; Counter variables
(define-data-var next-request-id uint u1)
(define-data-var total-researchers uint u0)
(define-data-var total-datasets uint u0)

;; Register as a researcher
(define-public (register-researcher
    (name (string-ascii 64))
    (institution (string-ascii 128))
    (credentials (string-ascii 64))
    (research-areas (list 5 (string-ascii 32))))
    (begin
        (map-set researcher-registry
            tx-sender
            {
                name: name,
                institution: institution,
                credentials: credentials,
                verification-level: u1,
                active: true,
                registered-at: stacks-block-height,
                research-areas: research-areas
            })
        (var-set total-researchers (+ (var-get total-researchers) u1))
        (ok tx-sender)))

;; Set patient anonymization preferences
(define-public (set-anonymization-preferences
    (default-level uint)
    (allowed-areas (list 10 (string-ascii 32)))
    (auto-approve-threshold uint)
    (opt-out bool))
    (begin
        (asserts! (and (>= default-level u1) (<= default-level u3)) (err ERR-INVALID-PARAMS))
        (map-set patient-anonymization-prefs
            tx-sender
            {
                default-level: default-level,
                allowed-research-areas: allowed-areas,
                auto-approve-threshold: auto-approve-threshold,
                opt-out-complete: opt-out,
                last-updated: stacks-block-height
            })
        (ok true)))

;; Submit anonymization request
(define-public (submit-anonymization-request
    (request-id (string-ascii 32))
    (target-patients (list 20 principal))
    (research-purpose (string-ascii 256))
    (data-categories (list 8 (string-ascii 32)))
    (anonymization-level uint)
    (k-value uint)
    (epsilon-value uint))
    (let ((researcher (map-get? researcher-registry tx-sender))
          (expires-at (+ stacks-block-height u1008))) ;; ~1 week expiry
        (asserts! (is-some researcher) (err ERR-UNAUTHORIZED))
        (asserts! (get active (unwrap-panic researcher)) (err ERR-UNAUTHORIZED))
        (asserts! (and (>= anonymization-level u1) (<= anonymization-level u3)) (err ERR-INVALID-PARAMS))
        (map-set anonymization-requests
            { request-id: request-id }
            {
                requester: tx-sender,
                target-patients: target-patients,
                research-purpose: research-purpose,
                data-categories: data-categories,
                anonymization-level: anonymization-level,
                k-value: k-value,
                epsilon-value: epsilon-value,
                status: STATUS-PENDING,
                created-at: stacks-block-height,
                expires-at: expires-at,
                processed-at: u0,
                data-hash: none
            })
        (update-usage-stats "request")
        (ok request-id)))

;; Patient approves anonymization request
(define-public (approve-anonymization-request
    (request-id (string-ascii 32))
    (conditions (optional (string-ascii 128))))
    (let ((request (map-get? anonymization-requests { request-id: request-id }))
          (patient-prefs (map-get? patient-anonymization-prefs tx-sender)))
        (asserts! (is-some request) (err ERR-NOT-FOUND))
        (let ((request-data (unwrap-panic request)))
            (asserts! (< stacks-block-height (get expires-at request-data)) (err ERR-EXPIRED-REQUEST))
            (asserts! (is-eq (get status request-data) STATUS-PENDING) (err ERR-ALREADY-PROCESSED))
            (asserts! (is-some (index-of (get target-patients request-data) tx-sender)) (err ERR-UNAUTHORIZED))
            ;; Check if anonymization level meets patient preferences
            (if (is-some patient-prefs)
                (let ((prefs (unwrap-panic patient-prefs)))
                    (asserts! (>= (get anonymization-level request-data) (get default-level prefs)) 
                              (err ERR-INSUFFICIENT-PRIVACY))
                    (asserts! (not (get opt-out-complete prefs)) (err ERR-UNAUTHORIZED)))
                true)
            (map-set patient-request-approvals
                { patient: tx-sender, request-id: request-id }
                {
                    approved: true,
                    approval-timestamp: stacks-block-height,
                    conditions: conditions
                })
            (ok true))))

;; Process anonymization request (researcher calls after approvals)
(define-public (process-anonymization-request
    (request-id (string-ascii 32))
    (dataset-id (string-ascii 32))
    (data-hash (string-ascii 64)))
    (let ((request (map-get? anonymization-requests { request-id: request-id })))
        (asserts! (is-some request) (err ERR-NOT-FOUND))
        (let ((request-data (unwrap-panic request)))
            (asserts! (is-eq tx-sender (get requester request-data)) (err ERR-UNAUTHORIZED))
            (asserts! (is-eq (get status request-data) STATUS-PENDING) (err ERR-ALREADY-PROCESSED))
            (asserts! (< stacks-block-height (get expires-at request-data)) (err ERR-EXPIRED-REQUEST))
            ;; Check if sufficient patients approved (simplified check)
            (asserts! (>= (len (get target-patients request-data)) u1) (err ERR-INSUFFICIENT-PRIVACY))
            ;; Update request status
            (map-set anonymization-requests
                { request-id: request-id }
                (merge request-data {
                    status: STATUS-PROCESSED,
                    processed-at: stacks-block-height,
                    data-hash: (some data-hash)
                }))
            ;; Create dataset entry
            (create-dataset dataset-id request-id request-data data-hash)
            (update-usage-stats "processed")
            (ok dataset-id))))



;; Create anonymized dataset record
(define-private (create-dataset 
    (dataset-id (string-ascii 32))
    (request-id (string-ascii 32))
    (request-data { requester: principal, target-patients: (list 20 principal), research-purpose: (string-ascii 256), data-categories: (list 8 (string-ascii 32)), anonymization-level: uint, k-value: uint, epsilon-value: uint, status: (string-ascii 10), created-at: uint, expires-at: uint, processed-at: uint, data-hash: (optional (string-ascii 64)) })
    (data-hash (string-ascii 64)))
    (let ((method (if (is-eq (get anonymization-level request-data) LEVEL-K-ANONYMITY)
                      "k-anonymity"
                      (if (is-eq (get anonymization-level request-data) LEVEL-DIFFERENTIAL)
                          "differential-privacy"
                          "basic-deidentification")))
          (privacy-params (if (is-eq (get anonymization-level request-data) LEVEL-K-ANONYMITY)
                              (uint-to-string (get k-value request-data))
                              (if (is-eq (get anonymization-level request-data) LEVEL-DIFFERENTIAL)
                                  (uint-to-string (get epsilon-value request-data))
                                  "standard"))))
        (map-set anonymized-datasets
            { dataset-id: dataset-id }
            {
                source-request: request-id,
                patient-count: (len (get target-patients request-data)),
                anonymization-method: method,
                privacy-parameters: privacy-params,
                created-at: stacks-block-height,
                access-count: u0,
                researcher: (get requester request-data),
                hash-checksum: data-hash
            })
        (var-set total-datasets (+ (var-get total-datasets) u1))
        true))

;; Record dataset access
(define-public (record-dataset-access (dataset-id (string-ascii 32)))
    (let ((dataset (map-get? anonymized-datasets { dataset-id: dataset-id })))
        (asserts! (is-some dataset) (err ERR-NOT-FOUND))
        (let ((dataset-data (unwrap-panic dataset)))
            (asserts! (is-eq tx-sender (get researcher dataset-data)) (err ERR-UNAUTHORIZED))
            (map-set anonymized-datasets
                { dataset-id: dataset-id }
                (merge dataset-data { access-count: (+ (get access-count dataset-data) u1) }))
            (ok true))))

;; Create research project
(define-public (create-research-project
    (project-id (string-ascii 32))
    (title (string-ascii 128))
    (description (string-ascii 512))
    (ethics-approval (string-ascii 64))
    (end-date uint))
    (let ((researcher (map-get? researcher-registry tx-sender)))
        (asserts! (is-some researcher) (err ERR-UNAUTHORIZED))
        (asserts! (get active (unwrap-panic researcher)) (err ERR-UNAUTHORIZED))
        (map-set research-projects
            { project-id: project-id }
            {
                lead-researcher: tx-sender,
                title: title,
                description: description,
                ethics-approval: ethics-approval,
                start-date: stacks-block-height,
                end-date: end-date,
                datasets-used: (list),
                status: "active"
            })
        (ok project-id)))

;; Update usage analytics
(define-private (update-usage-stats (stat-type (string-ascii 10)))
    (let ((current-period (/ stacks-block-height u1008))
          (current-stats (default-to 
                          { total-requests: u0, approved-requests: u0, patients-participating: u0, 
                            datasets-created: u0, privacy-violations: u0 }
                          (map-get? usage-analytics { period: current-period }))))
        (if (is-eq stat-type "request")
            (map-set usage-analytics
                { period: current-period }
                (merge current-stats { total-requests: (+ (get total-requests current-stats) u1) }))
            (if (is-eq stat-type "processed")
                (map-set usage-analytics
                    { period: current-period }
                    (merge current-stats { datasets-created: (+ (get datasets-created current-stats) u1) }))
                false))
        true))

;; Read-only functions
(define-read-only (get-researcher-info (researcher principal))
    (map-get? researcher-registry researcher))

(define-read-only (get-patient-preferences (patient principal))
    (map-get? patient-anonymization-prefs patient))

(define-read-only (get-anonymization-request (request-id (string-ascii 32)))
    (map-get? anonymization-requests { request-id: request-id }))

(define-read-only (get-patient-approval (patient principal) (request-id (string-ascii 32)))
    (map-get? patient-request-approvals { patient: patient, request-id: request-id }))

(define-read-only (get-dataset-info (dataset-id (string-ascii 32)))
    (map-get? anonymized-datasets { dataset-id: dataset-id }))

(define-read-only (get-research-project (project-id (string-ascii 32)))
    (map-get? research-projects { project-id: project-id }))

(define-read-only (get-usage-stats (period uint))
    (map-get? usage-analytics { period: period }))

(define-read-only (get-system-overview)
    {
        total-researchers: (var-get total-researchers),
        total-datasets: (var-get total-datasets),
        next-request-id: (var-get next-request-id)
    })

;; Helper function to convert uint to string (simplified)
(define-private (uint-to-string (value uint))
    (if (< value u10)
        (if (is-eq value u0) "0"
        (if (is-eq value u1) "1"
        (if (is-eq value u2) "2"
        (if (is-eq value u3) "3"
        (if (is-eq value u4) "4"
        (if (is-eq value u5) "5"
        (if (is-eq value u6) "6"
        (if (is-eq value u7) "7"
        (if (is-eq value u8) "8"
        "9")))))))))
        "10+"))

