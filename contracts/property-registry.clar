;; Intellectual Property Registry Contract
;; Registers and protects intellectual property rights on blockchain

(define-constant CONTRACT_OWNER tx-sender)
(define-constant ERR_UNAUTHORIZED (err u401))
(define-constant ERR_NOT_FOUND (err u404))
(define-constant ERR_ALREADY_EXISTS (err u409))
(define-constant ERR_INVALID_INPUT (err u400))

;; IP Types
(define-constant IP_TYPE_PATENT u1)
(define-constant IP_TYPE_TRADEMARK u2)
(define-constant IP_TYPE_COPYRIGHT u3)

;; Data maps
(define-map ip-registry
  { ip-id: uint }
  {
    owner: principal,
    ip-type: uint,
    title: (string-ascii 256),
    description: (string-ascii 1024),
    hash: (buff 32),
    registration-block: uint,
    expiry-block: (optional uint),
    status: uint  ;; 1=active, 2=expired, 3=revoked
  }
)

(define-map prior-art
  { hash: (buff 32) }
  {
    ip-id: uint,
    timestamp-block: uint,
    submitter: principal
  }
)

(define-map user-ip-count
  { user: principal }
  { count: uint }
)

;; Data vars
(define-data-var next-ip-id uint u1)
(define-data-var registration-fee uint u1000000) ;; 1 STX in microSTX

;; Private functions
(define-private (is-valid-ip-type (ip-type uint))
  (or (is-eq ip-type IP_TYPE_PATENT)
      (or (is-eq ip-type IP_TYPE_TRADEMARK)
          (is-eq ip-type IP_TYPE_COPYRIGHT))))

(define-private (get-expiry-blocks (ip-type uint))
  (if (is-eq ip-type IP_TYPE_PATENT)
      (some u1051200) ;; ~20 years in blocks
      (if (is-eq ip-type IP_TYPE_TRADEMARK)
          (some u525600) ;; ~10 years in blocks
          none))) ;; Copyright has no expiry

;; Read-only functions
(define-read-only (get-ip-registration (ip-id uint))
  (map-get? ip-registry { ip-id: ip-id }))

(define-read-only (get-prior-art (hash (buff 32)))
  (map-get? prior-art { hash: hash }))

(define-read-only (get-user-ip-count (user principal))
  (default-to u0 (get count (map-get? user-ip-count { user: user }))))

(define-read-only (get-next-ip-id)
  (var-get next-ip-id))

(define-read-only (get-registration-fee)
  (var-get registration-fee))

(define-read-only (verify-prior-art (hash (buff 32)) (claimed-timestamp uint))
  (match (map-get? prior-art { hash: hash })
    prior-art-data (< (get timestamp-block prior-art-data) claimed-timestamp)
    false))

;; Public functions
(define-public (register-ip (ip-type uint) (title (string-ascii 256)) (description (string-ascii 1024)) (content-hash (buff 32)))
  (let (
    (ip-id (var-get next-ip-id))
    (current-block stacks-block-height)
    (expiry-block (get-expiry-blocks ip-type))
    (fee (var-get registration-fee))
  )
    (asserts! (is-valid-ip-type ip-type) ERR_INVALID_INPUT)
    (asserts! (> (len title) u0) ERR_INVALID_INPUT)
    (asserts! (> (len description) u0) ERR_INVALID_INPUT)
    (asserts! (is-none (map-get? prior-art { hash: content-hash })) ERR_ALREADY_EXISTS)

    ;; Transfer registration fee
    (try! (stx-transfer? fee tx-sender CONTRACT_OWNER))

    ;; Register IP
    (map-set ip-registry
      { ip-id: ip-id }
      {
        owner: tx-sender,
        ip-type: ip-type,
        title: title,
        description: description,
        hash: content-hash,
        registration-block: current-block,
        expiry-block: expiry-block,
        status: u1
      })

    ;; Record prior art
    (map-set prior-art
      { hash: content-hash }
      {
        ip-id: ip-id,
        timestamp-block: current-block,
        submitter: tx-sender
      })

    ;; Update counters
    (map-set user-ip-count
      { user: tx-sender }
      { count: (+ (get-user-ip-count tx-sender) u1) })

    (var-set next-ip-id (+ ip-id u1))
    (ok ip-id)))

(define-public (transfer-ip (ip-id uint) (new-owner principal))
  (let (
    (ip-data (unwrap! (map-get? ip-registry { ip-id: ip-id }) ERR_NOT_FOUND))
  )
    (asserts! (is-eq (get owner ip-data) tx-sender) ERR_UNAUTHORIZED)
    (asserts! (is-eq (get status ip-data) u1) ERR_INVALID_INPUT)

    (map-set ip-registry
      { ip-id: ip-id }
      (merge ip-data { owner: new-owner }))

    ;; Update counters
    (map-set user-ip-count
      { user: tx-sender }
      { count: (- (get-user-ip-count tx-sender) u1) })

    (map-set user-ip-count
      { user: new-owner }
      { count: (+ (get-user-ip-count new-owner) u1) })

    (ok true)))

(define-public (renew-ip (ip-id uint))
  (let (
    (ip-data (unwrap! (map-get? ip-registry { ip-id: ip-id }) ERR_NOT_FOUND))
    (current-block stacks-block-height)
    (extension-blocks (get-expiry-blocks (get ip-type ip-data)))
  )
    (asserts! (is-eq (get owner ip-data) tx-sender) ERR_UNAUTHORIZED)
    (asserts! (is-some extension-blocks) ERR_INVALID_INPUT)
    (asserts! (is-eq (get status ip-data) u1) ERR_INVALID_INPUT)

    ;; Transfer renewal fee (same as registration)
    (try! (stx-transfer? (var-get registration-fee) tx-sender CONTRACT_OWNER))

    (map-set ip-registry
      { ip-id: ip-id }
      (merge ip-data {
        expiry-block: (some (+ current-block (unwrap-panic extension-blocks)))
      }))

    (ok true)))

(define-public (revoke-ip (ip-id uint))
  (let (
    (ip-data (unwrap! (map-get? ip-registry { ip-id: ip-id }) ERR_NOT_FOUND))
  )
    (asserts! (is-eq (get owner ip-data) tx-sender) ERR_UNAUTHORIZED)
    (asserts! (is-eq (get status ip-data) u1) ERR_INVALID_INPUT)

    (map-set ip-registry
      { ip-id: ip-id }
      (merge ip-data { status: u3 }))

    (ok true)))

;; Admin functions
(define-public (set-registration-fee (new-fee uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (var-set registration-fee new-fee)
    (ok true)))

(define-public (expire-ip (ip-id uint))
  (let (
    (ip-data (unwrap! (map-get? ip-registry { ip-id: ip-id }) ERR_NOT_FOUND))
    (current-block stacks-block-height)
  )
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (asserts! (is-some (get expiry-block ip-data)) ERR_INVALID_INPUT)
    (asserts! (>= current-block (unwrap-panic (get expiry-block ip-data))) ERR_INVALID_INPUT)

    (map-set ip-registry
      { ip-id: ip-id }
      (merge ip-data { status: u2 }))

    (ok true)))
