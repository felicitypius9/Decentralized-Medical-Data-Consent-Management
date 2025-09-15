;; Medical Data Breach Notification System
;; Automated breach detection, notification, and regulatory compliance tracking

;; Error constants
(define-constant ERR-NOT-AUTHORIZED u401)
(define-constant ERR-BREACH-NOT-FOUND u404)
(define-constant ERR-INVALID-PARAMS u400)
(define-constant ERR-ALREADY-REPORTED u409)
(define-constant ERR-DEADLINE-PASSED u410)

;; Breach severity levels
(define-constant SEVERITY-LOW u1)
(define-constant SEVERITY-MEDIUM u2) 
(define-constant SEVERITY-HIGH u3)
(define-constant SEVERITY-CRITICAL u4)

;; Notification status
(define-constant STATUS-DETECTED "detected")
(define-constant STATUS-INVESTIGATING "investigating")
(define-constant STATUS-CONFIRMED "confirmed")
(define-constant STATUS-NOTIFIED "notified")
(define-constant STATUS-RESOLVED "resolved")

;; Regulatory deadlines (in blocks)
(define-constant HIPAA-DEADLINE u4320) ;; ~72 hours
(define-constant GDPR-DEADLINE u1008)  ;; ~72 hours
(define-constant BREACH-REPORT-DEADLINE u21600) ;; ~30 days

;; Data breach incidents
(define-map breach-incidents
    { incident-id: (string-ascii 32) }
    {
        reporter: principal,
        affected-patients: (list 100 principal),
        breach-type: (string-ascii 32),
        severity: uint,
        description: (string-ascii 256),
        detected-at: uint,
        confirmed-at: uint,
        data-types-affected: (list 10 (string-ascii 32)),
        estimated-records: uint,
        root-cause: (optional (string-ascii 256)),
        status: (string-ascii 15)
    })

;; Patient notifications tracking
(define-map patient-notifications
    { incident-id: (string-ascii 32), patient: principal }
    {
        notification-sent: bool,
        notification-time: uint,
        acknowledgment-received: bool,
        acknowledgment-time: uint,
        contact-method: (string-ascii 20)
    })

;; Regulatory notifications
(define-map regulatory-notifications
    { incident-id: (string-ascii 32), authority: (string-ascii 32) }
    {
        notification-required: bool,
        deadline: uint,
        notification-sent: bool,
        notification-time: uint,
        confirmation-received: bool,
        reference-number: (optional (string-ascii 32))
    })

;; Breach response actions
(define-map response-actions
    { incident-id: (string-ascii 32), action-id: uint }
    {
        action-type: (string-ascii 32),
        description: (string-ascii 256),
        assigned-to: principal,
        due-date: uint,
        completed: bool,
        completion-time: uint
    })

;; Counter variables
(define-data-var total-breaches uint u0)
(define-data-var next-action-id uint u1)

;; Report a data breach incident
(define-public (report-breach
    (incident-id (string-ascii 32))
    (affected-patients (list 100 principal))
    (breach-type (string-ascii 32))
    (severity uint)
    (description (string-ascii 256))
    (data-types (list 10 (string-ascii 32)))
    (estimated-records uint))
    (begin
        ;; Validate inputs
        (asserts! (and (>= severity u1) (<= severity u4)) (err ERR-INVALID-PARAMS))
        (asserts! (> estimated-records u0) (err ERR-INVALID-PARAMS))
        (asserts! (is-none (map-get? breach-incidents { incident-id: incident-id })) (err ERR-ALREADY-REPORTED))
        
        ;; Create breach incident record
        (map-set breach-incidents
            { incident-id: incident-id }
            {
                reporter: tx-sender,
                affected-patients: affected-patients,
                breach-type: breach-type,
                severity: severity,
                description: description,
                detected-at: stacks-block-height,
                confirmed-at: u0,
                data-types-affected: data-types,
                estimated-records: estimated-records,
                root-cause: none,
                status: STATUS-DETECTED
            })
        
        ;; Auto-create regulatory notifications based on severity
        (begin
            (if (>= severity SEVERITY-HIGH)
                (begin
                    (map-set regulatory-notifications
                        { incident-id: incident-id, authority: "HIPAA" }
                        {
                            notification-required: true,
                            deadline: (+ stacks-block-height HIPAA-DEADLINE),
                            notification-sent: false,
                            notification-time: u0,
                            confirmation-received: false,
                            reference-number: none
                        })
                    (map-set regulatory-notifications
                        { incident-id: incident-id, authority: "GDPR" }
                        {
                            notification-required: true,
                            deadline: (+ stacks-block-height GDPR-DEADLINE),
                            notification-sent: false,
                            notification-time: u0,
                            confirmation-received: false,
                            reference-number: none
                        })
                    true)
                true))
        
        (var-set total-breaches (+ (var-get total-breaches) u1))
        
        ;; Note: Audit logging can be added later
        
        (ok incident-id)))

;; Confirm breach after investigation
(define-public (confirm-breach
    (incident-id (string-ascii 32))
    (root-cause (string-ascii 256)))
    (let ((incident (unwrap! (map-get? breach-incidents { incident-id: incident-id }) (err ERR-BREACH-NOT-FOUND))))
        (asserts! (is-eq (get reporter incident) tx-sender) (err ERR-NOT-AUTHORIZED))
        (asserts! (is-eq (get status incident) STATUS-DETECTED) (err ERR-INVALID-PARAMS))
        
        ;; Update incident status
        (map-set breach-incidents
            { incident-id: incident-id }
            (merge incident {
                confirmed-at: stacks-block-height,
                root-cause: (some root-cause),
                status: STATUS-CONFIRMED
            }))
        
        (ok true)))

;; Patient acknowledges breach notification
(define-public (acknowledge-breach-notification (incident-id (string-ascii 32)))
    (let ((notification (map-get? patient-notifications { incident-id: incident-id, patient: tx-sender })))
        (if (is-some notification)
            (begin
                (map-set patient-notifications
                    { incident-id: incident-id, patient: tx-sender }
                    (merge (unwrap-panic notification) {
                        acknowledgment-received: true,
                        acknowledgment-time: stacks-block-height
                    }))
                (ok true))
            (err ERR-BREACH-NOT-FOUND))))

;; Submit regulatory notification
(define-public (submit-regulatory-notification
    (incident-id (string-ascii 32))
    (authority (string-ascii 32))
    (reference-number (string-ascii 32)))
    (let ((incident (unwrap! (map-get? breach-incidents { incident-id: incident-id }) (err ERR-BREACH-NOT-FOUND)))
          (reg-notification (unwrap! (map-get? regulatory-notifications { incident-id: incident-id, authority: authority }) (err ERR-BREACH-NOT-FOUND))))
        (asserts! (is-eq (get reporter incident) tx-sender) (err ERR-NOT-AUTHORIZED))
        (asserts! (< stacks-block-height (get deadline reg-notification)) (err ERR-DEADLINE-PASSED))
        
        (map-set regulatory-notifications
            { incident-id: incident-id, authority: authority }
            (merge reg-notification {
                notification-sent: true,
                notification-time: stacks-block-height,
                reference-number: (some reference-number)
            }))
        
        (ok true)))

;; Add response action
(define-public (add-response-action
    (incident-id (string-ascii 32))
    (action-type (string-ascii 32))
    (description (string-ascii 256))
    (assigned-to principal)
    (due-date uint))
    (let ((incident (unwrap! (map-get? breach-incidents { incident-id: incident-id }) (err ERR-BREACH-NOT-FOUND)))
          (action-id (var-get next-action-id)))
        (asserts! (is-eq (get reporter incident) tx-sender) (err ERR-NOT-AUTHORIZED))
        
        (map-set response-actions
            { incident-id: incident-id, action-id: action-id }
            {
                action-type: action-type,
                description: description,
                assigned-to: assigned-to,
                due-date: due-date,
                completed: false,
                completion-time: u0
            })
        
        (var-set next-action-id (+ action-id u1))
        (ok action-id)))

;; Mark response action as complete
(define-public (complete-response-action
    (incident-id (string-ascii 32))
    (action-id uint))
    (let ((action (unwrap! (map-get? response-actions { incident-id: incident-id, action-id: action-id }) (err ERR-BREACH-NOT-FOUND))))
        (asserts! (is-eq (get assigned-to action) tx-sender) (err ERR-NOT-AUTHORIZED))
        
        (map-set response-actions
            { incident-id: incident-id, action-id: action-id }
            (merge action {
                completed: true,
                completion-time: stacks-block-height
            }))
        
        (ok true)))

;; Read-only functions
(define-read-only (get-breach-incident (incident-id (string-ascii 32)))
    (map-get? breach-incidents { incident-id: incident-id }))

(define-read-only (get-patient-notification (incident-id (string-ascii 32)) (patient principal))
    (map-get? patient-notifications { incident-id: incident-id, patient: patient }))

(define-read-only (get-regulatory-notification (incident-id (string-ascii 32)) (authority (string-ascii 32)))
    (map-get? regulatory-notifications { incident-id: incident-id, authority: authority }))

(define-read-only (get-response-action (incident-id (string-ascii 32)) (action-id uint))
    (map-get? response-actions { incident-id: incident-id, action-id: action-id }))

(define-read-only (get-total-breaches)
    (var-get total-breaches))

;; Check if regulatory deadlines are approaching
(define-read-only (check-regulatory-deadlines (incident-id (string-ascii 32)) (authority (string-ascii 32)))
    (let ((reg-notification (map-get? regulatory-notifications { incident-id: incident-id, authority: authority })))
        (if (is-some reg-notification)
            (let ((notification-data (unwrap-panic reg-notification)))
                (if (get notification-sent notification-data)
                    { deadline-status: "completed", blocks-remaining: u0 }
                    { deadline-status: "pending", blocks-remaining: (- (get deadline notification-data) stacks-block-height) }))
            { deadline-status: "not-required", blocks-remaining: u0 })))
