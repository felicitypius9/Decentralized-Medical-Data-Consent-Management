(define-constant ERR-UNAUTHORIZED u401)
(define-constant ERR-CHALLENGE-EXPIRED u402)
(define-constant ERR-CHALLENGE-NOT-FOUND u404)
(define-constant ERR-INVALID-PROOF u403)
(define-constant ERR-ALREADY-VERIFIED u409)

(define-constant CHALLENGE-DURATION u144)

(define-map biometric-challenges
    { challenge-id: (string-ascii 32) }
    {
        patient: principal,
        provider: principal,
        challenge-hash: (string-ascii 64),
        created-at: uint,
        expires-at: uint,
        verification-status: (string-ascii 10),
        access-purpose: (string-ascii 64),
        data-categories: (list 5 (string-ascii 32))
    })

(define-map biometric-verifications
    { challenge-id: (string-ascii 32) }
    {
        verifier: principal,
        proof-hash: (string-ascii 64),
        verified-at: uint,
        method: (string-ascii 20),
        confidence-score: uint
    })

(define-map patient-biometric-registry
    principal
    {
        fingerprint-hash: (optional (string-ascii 64)),
        voice-hash: (optional (string-ascii 64)),
        iris-hash: (optional (string-ascii 64)),
        face-hash: (optional (string-ascii 64)),
        last-updated: uint,
        active-methods: (list 4 (string-ascii 20))
    })

(define-map provider-verification-stats
    principal
    {
        total-challenges: uint,
        successful-verifications: uint,
        failed-attempts: uint,
        last-challenge: uint
    })

(define-data-var total-challenges uint u0)
(define-data-var successful-verifications uint u0)

(define-public (register-biometric 
    (method (string-ascii 20))
    (biometric-hash (string-ascii 64)))
    (let ((current-registry (default-to 
            {
                fingerprint-hash: none,
                voice-hash: none,
                iris-hash: none,
                face-hash: none,
                last-updated: u0,
                active-methods: (list)
            }
            (map-get? patient-biometric-registry tx-sender)))
          (updated-registry 
            (if (is-eq method "fingerprint")
                (merge current-registry 
                    { fingerprint-hash: (some biometric-hash),
                      last-updated: stacks-block-height })
                (if (is-eq method "voice")
                    (merge current-registry 
                        { voice-hash: (some biometric-hash),
                          last-updated: stacks-block-height })
                    (if (is-eq method "iris")
                        (merge current-registry 
                            { iris-hash: (some biometric-hash),
                              last-updated: stacks-block-height })
                        (merge current-registry 
                            { face-hash: (some biometric-hash),
                              last-updated: stacks-block-height }))))))
        (map-set patient-biometric-registry 
            tx-sender 
            (merge updated-registry 
                { active-methods: (unwrap-panic (as-max-len? 
                    (append (get active-methods updated-registry) method) u4)) }))
        (ok true)))

(define-public (create-biometric-challenge
    (challenge-id (string-ascii 32))
    (patient principal)
    (challenge-hash (string-ascii 64))
    (access-purpose (string-ascii 64))
    (data-categories (list 5 (string-ascii 32))))
    (let ((expires-at (+ stacks-block-height CHALLENGE-DURATION))
          (provider-stats (default-to 
            { total-challenges: u0, successful-verifications: u0, failed-attempts: u0, last-challenge: u0 }
            (map-get? provider-verification-stats tx-sender))))
        (map-set biometric-challenges
            { challenge-id: challenge-id }
            {
                patient: patient,
                provider: tx-sender,
                challenge-hash: challenge-hash,
                created-at: stacks-block-height,
                expires-at: expires-at,
                verification-status: "pending",
                access-purpose: access-purpose,
                data-categories: data-categories
            })
        (map-set provider-verification-stats
            tx-sender
            (merge provider-stats 
                { total-challenges: (+ (get total-challenges provider-stats) u1),
                  last-challenge: stacks-block-height }))
        (var-set total-challenges (+ (var-get total-challenges) u1))
        (ok challenge-id)))

(define-public (verify-biometric-challenge
    (challenge-id (string-ascii 32))
    (proof-hash (string-ascii 64))
    (method (string-ascii 20))
    (confidence-score uint))
    (let ((challenge (map-get? biometric-challenges { challenge-id: challenge-id }))
          (patient-registry (map-get? patient-biometric-registry tx-sender)))
        (if (is-none challenge)
            (err ERR-CHALLENGE-NOT-FOUND)
            (let ((challenge-data (unwrap-panic challenge)))
                (if (> stacks-block-height (get expires-at challenge-data))
                    (err ERR-CHALLENGE-EXPIRED)
                    (if (not (is-eq (get patient challenge-data) tx-sender))
                        (err ERR-UNAUTHORIZED)
                        (if (is-eq (get verification-status challenge-data) "verified")
                            (err ERR-ALREADY-VERIFIED)
                            (let ((verification-valid (verify-biometric-proof method proof-hash patient-registry))
                                  (provider-stats (default-to 
                                    { total-challenges: u0, successful-verifications: u0, failed-attempts: u0, last-challenge: u0 }
                                    (map-get? provider-verification-stats (get provider challenge-data)))))
                                (if verification-valid
                                    (begin
                                        (map-set biometric-verifications
                                            { challenge-id: challenge-id }
                                            {
                                                verifier: tx-sender,
                                                proof-hash: proof-hash,
                                                verified-at: stacks-block-height,
                                                method: method,
                                                confidence-score: confidence-score
                                            })
                                        (map-set biometric-challenges
                                            { challenge-id: challenge-id }
                                            (merge challenge-data { verification-status: "verified" }))
                                        (map-set provider-verification-stats
                                            (get provider challenge-data)
                                            (merge provider-stats 
                                                { successful-verifications: (+ (get successful-verifications provider-stats) u1) }))
                                        (var-set successful-verifications (+ (var-get successful-verifications) u1))
                                        (ok true))
                                    (begin
                                        (map-set provider-verification-stats
                                            (get provider challenge-data)
                                            (merge provider-stats 
                                                { failed-attempts: (+ (get failed-attempts provider-stats) u1) }))
                                        (err ERR-INVALID-PROOF)))))))))))

(define-private (verify-biometric-proof 
    (method (string-ascii 20)) 
    (proof-hash (string-ascii 64)) 
    (registry (optional { fingerprint-hash: (optional (string-ascii 64)), 
                         voice-hash: (optional (string-ascii 64)), 
                         iris-hash: (optional (string-ascii 64)), 
                         face-hash: (optional (string-ascii 64)), 
                         last-updated: uint, 
                         active-methods: (list 4 (string-ascii 20)) })))
    (if (is-none registry)
        false
        (let ((reg-data (unwrap-panic registry)))
            (if (is-eq method "fingerprint")
                (match (get fingerprint-hash reg-data)
                    hash (is-eq hash proof-hash)
                    false)
                (if (is-eq method "voice")
                    (match (get voice-hash reg-data)
                        hash (is-eq hash proof-hash)
                        false)
                    (if (is-eq method "iris")
                        (match (get iris-hash reg-data)
                            hash (is-eq hash proof-hash)
                            false)
                        (match (get face-hash reg-data)
                            hash (is-eq hash proof-hash)
                            false)))))))

(define-public (revoke-biometric-challenge (challenge-id (string-ascii 32)))
    (let ((challenge (map-get? biometric-challenges { challenge-id: challenge-id })))
        (if (is-none challenge)
            (err ERR-CHALLENGE-NOT-FOUND)
            (let ((challenge-data (unwrap-panic challenge)))
                (if (and 
                    (or (is-eq tx-sender (get patient challenge-data))
                        (is-eq tx-sender (get provider challenge-data)))
                    (is-eq (get verification-status challenge-data) "pending"))
                    (begin
                        (map-set biometric-challenges
                            { challenge-id: challenge-id }
                            (merge challenge-data { verification-status: "revoked" }))
                        (ok true))
                    (err ERR-UNAUTHORIZED))))))

(define-read-only (get-biometric-challenge (challenge-id (string-ascii 32)))
    (map-get? biometric-challenges { challenge-id: challenge-id }))

(define-read-only (get-verification-details (challenge-id (string-ascii 32)))
    (map-get? biometric-verifications { challenge-id: challenge-id }))

(define-read-only (get-patient-biometrics (patient principal))
    (map-get? patient-biometric-registry patient))

(define-read-only (get-provider-stats (provider principal))
    (map-get? provider-verification-stats provider))

(define-read-only (get-system-stats)
    {
        total-challenges: (var-get total-challenges),
        successful-verifications: (var-get successful-verifications),
        success-rate: (if (> (var-get total-challenges) u0)
                        (/ (* (var-get successful-verifications) u100) (var-get total-challenges))
                        u0)
    })

(define-read-only (is-challenge-valid (challenge-id (string-ascii 32)))
    (let ((challenge (map-get? biometric-challenges { challenge-id: challenge-id })))
        (if (is-none challenge)
            false
            (let ((challenge-data (unwrap-panic challenge)))
                (and 
                    (is-eq (get verification-status challenge-data) "verified")
                    (< stacks-block-height (get expires-at challenge-data)))))))

(define-public (cleanup-expired-challenges (challenge-ids (list 10 (string-ascii 32))))
    (ok (map cleanup-single-challenge challenge-ids)))

(define-private (cleanup-single-challenge (challenge-id (string-ascii 32)))
    (let ((challenge (map-get? biometric-challenges { challenge-id: challenge-id })))
        (if (is-some challenge)
            (let ((challenge-data (unwrap-panic challenge)))
                (if (> stacks-block-height (get expires-at challenge-data))
                    (begin
                        (map-set biometric-challenges
                            { challenge-id: challenge-id }
                            (merge challenge-data { verification-status: "expired" }))
                        true)
                    false))
            false)))
