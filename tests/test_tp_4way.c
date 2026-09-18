/* N-way (4-rank) TCP gate exchange over a loopback mesh.
 *
 * Unlike test_tp_tcp this exercises the peer-indexed in-region: each rank
 * exchanges with every other rank and every rank's in-region must hold each
 * peer's partial at the peer-indexed offset, not a single shared slot.
 * Registration (ds4_tp_create / hello / data mesh) needs real TCP listeners,
 * so the mesh data links are socketpairs wired directly into peers[].data_fd
 * — exactly what the exchange primitives consume.
 */
#include "../ds4_tp.c"
#include <assert.h>
#include <math.h>

#define NRANKS 4

typedef struct {
    ds4_tp tp;
    unsigned rank;
    int result;
} mesh_peer;

static void pattern(void *buffer, size_t bytes, unsigned rank) {
    unsigned char *p = buffer;
    for (size_t i = 0; i < bytes; i++) p[i] = (unsigned char)(i * 37 + rank);
}

static void *exchange(void *arg) {
    mesh_peer *p = arg;
    ds4_tp *tp = &p->tp;
    for (unsigned step = 0; step < 160; step++) {
        const unsigned layer = (step % 80) / 2, gate = step % 2;
        pattern(tp->slab + ds4_tp_slab_out_offset(tp, layer, gate),
                tp->vec_bytes, p->rank);
        if (!ds4_tp_gate_exchange(tp, layer, gate, step + 1)) {
            p->result = 0;
            return NULL;
        }
    }
    p->result = 1;
    return NULL;
}

/* Verify-block batch gate: every peer's rows land in its own peer-indexed
 * batch-in block for every layer. */
static void *batch_exchange(void *arg) {
    mesh_peer *p = arg;
    ds4_tp *tp = &p->tp;
    const unsigned n_layer = tp->n_layer;
    for (unsigned step = 0; step < 32; step++) {
        const unsigned layer = step % n_layer;
        const unsigned rows = (step % DS4_TP_BATCH_MAX_ROWS) + 1;
        pattern(tp->slab + ds4_tp_slab_batch_out_offset(tp, layer),
                rows * tp->vec_bytes, p->rank);
        if (!ds4_tp_batch_gate_exchange(tp, layer, rows, step + 1)) {
            p->result = 0;
            return NULL;
        }
    }
    p->result = 1;
    return NULL;
}

static void check_mesh(void) {
    const unsigned n_embd = 5120;
    const unsigned n_layer = 40;
    mesh_peer peer[NRANKS] = {0};
    pthread_t threads[NRANKS];

    /* One socketpair per unordered pair (i,j), i<j.  Rank i keeps one end as
     * peers[j].data_fd, rank j the other as peers[i].data_fd. */
    int fd[NRANKS][NRANKS];
    for (unsigned i = 0; i < NRANKS; i++)
        for (unsigned j = 0; j < NRANKS; j++) fd[i][j] = -1;
    for (unsigned i = 0; i < NRANKS; i++) {
        for (unsigned j = i + 1; j < NRANKS; j++) {
            int pair[2];
            assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
            fd[i][j] = pair[0];
            fd[j][i] = pair[1];
            for (unsigned k = 0; k < 2; k++) {
#ifdef SO_NOSIGPIPE
                int one = 1;
                assert(setsockopt(pair[k], SOL_SOCKET, SO_NOSIGPIPE,
                                  &one, sizeof(one)) == 0);
#endif
                assert(tp_socket_set_gate_timeout(pair[k], 1000));
            }
        }
    }

    for (unsigned r = 0; r < NRANKS; r++) {
        peer[r].rank = r;
        peer[r].tp = (ds4_tp){.rank = (int)r, .n_ranks = NRANKS,
            .n_layer = n_layer, .n_slots = n_layer * DS4_TP_GATES_PER_LAYER,
            .n_embd = n_embd, .vec_bytes = (uint64_t)n_embd * sizeof(float),
            .gate_timeout_ms = 1000};
        for (unsigned pr = 0; pr < NRANKS; pr++)
            peer[r].tp.peers[pr].data_fd = fd[r][pr];
        /* Scalar data_fd = the peer-rank-1 link (worker1); for N=2 it is the
         * sole link, for N>2 rank 1's own scalar is the leader link. */
        peer[r].tp.data_fd = r == 1 ? fd[r][0] : fd[r][1];
        tp_slab_layout(&peer[r].tp);
        peer[r].tp.slab = calloc(1, ds4_tp_slab_bytes_for(n_layer, n_embd, NRANKS));
        assert(peer[r].tp.slab);
        assert(pthread_create(&threads[r], NULL, exchange, &peer[r]) == 0);
    }
    for (unsigned r = 0; r < NRANKS; r++) {
        assert(pthread_join(threads[r], NULL) == 0 && peer[r].result);
    }

    /* Every rank's in-region must hold every peer's partial at the peer-
     * indexed offset for every step. */
    for (unsigned r = 0; r < NRANKS; r++) {
        ds4_tp *tp = &peer[r].tp;
        for (unsigned step = 0; step < 160; step++) {
            const unsigned layer = (step % 80) / 2, gate = step % 2;
            for (unsigned pr = 0; pr < NRANKS; pr++) {
                if (pr == r) continue;
                unsigned char *p = tp->slab +
                    ds4_tp_slab_in_offset_peer(tp, pr, layer, gate);
                for (unsigned i = 0; i < tp->vec_bytes; i++)
                    assert(p[i] == (unsigned char)(i * 37 + pr));
            }
        }
    }

    for (unsigned r = 0; r < NRANKS; r++) {
        free(peer[r].tp.slab);
        for (unsigned pr = 0; pr < NRANKS; pr++)
            if (fd[r][pr] >= 0) close(fd[r][pr]);
    }
    puts("4-way TCP mesh: peer-indexed in-regions hold each peer's partial: PASS");
}

static void check_batch_mesh(void) {
    const unsigned n_embd = 5120;
    const unsigned n_layer = 40;
    mesh_peer peer[NRANKS] = {0};
    pthread_t threads[NRANKS];

    int fd[NRANKS][NRANKS];
    for (unsigned i = 0; i < NRANKS; i++)
        for (unsigned j = 0; j < NRANKS; j++) fd[i][j] = -1;
    for (unsigned i = 0; i < NRANKS; i++) {
        for (unsigned j = i + 1; j < NRANKS; j++) {
            int pair[2];
            assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
            fd[i][j] = pair[0];
            fd[j][i] = pair[1];
            for (unsigned k = 0; k < 2; k++) {
#ifdef SO_NOSIGPIPE
                int one = 1;
                assert(setsockopt(pair[k], SOL_SOCKET, SO_NOSIGPIPE,
                                  &one, sizeof(one)) == 0);
#endif
                assert(tp_socket_set_gate_timeout(pair[k], 1000));
            }
        }
    }

    for (unsigned r = 0; r < NRANKS; r++) {
        peer[r].rank = r;
        peer[r].tp = (ds4_tp){.rank = (int)r, .n_ranks = NRANKS,
            .n_layer = n_layer, .n_slots = n_layer * DS4_TP_GATES_PER_LAYER,
            .n_embd = n_embd, .vec_bytes = (uint64_t)n_embd * sizeof(float),
            .gate_timeout_ms = 1000};
        for (unsigned pr = 0; pr < NRANKS; pr++)
            peer[r].tp.peers[pr].data_fd = fd[r][pr];
        peer[r].tp.data_fd = r == 1 ? fd[r][0] : fd[r][1];
        tp_slab_layout(&peer[r].tp);
        peer[r].tp.slab = calloc(1, ds4_tp_slab_bytes_for(n_layer, n_embd, NRANKS));
        assert(peer[r].tp.slab);
        assert(pthread_create(&threads[r], NULL, batch_exchange, &peer[r]) == 0);
    }
    for (unsigned r = 0; r < NRANKS; r++) {
        assert(pthread_join(threads[r], NULL) == 0 && peer[r].result);
    }

    /* Every rank's batch-in region must hold every peer's rows at the
     * peer-indexed offset for every exchanged layer. */
    for (unsigned r = 0; r < NRANKS; r++) {
        ds4_tp *tp = &peer[r].tp;
        for (unsigned step = 0; step < 32; step++) {
            const unsigned layer = step % tp->n_layer;
            const unsigned rows = (step % DS4_TP_BATCH_MAX_ROWS) + 1;
            for (unsigned pr = 0; pr < NRANKS; pr++) {
                if (pr == r) continue;
                unsigned char *p = tp->slab +
                    ds4_tp_slab_batch_in_offset_peer(tp, pr, layer);
                for (unsigned i = 0; i < rows * tp->vec_bytes; i++)
                    assert(p[i] == (unsigned char)(i * 37 + pr));
            }
        }
    }
    for (unsigned r = 0; r < NRANKS; r++) {
        free(peer[r].tp.slab);
        for (unsigned pr = 0; pr < NRANKS; pr++)
            if (fd[r][pr] >= 0) close(fd[r][pr]);
    }
    puts("4-way TCP mesh: peer-indexed batch-in blocks hold each peer's rows: PASS");
}

/* N-way reduce: block 0 (in_offset) must become the sum of every peer's
 * partial, not just the lowest peer.  Rank 0's peers are 1,2,3; peer 1 owns
 * block 0, peers 2,3 own blocks 1,2. */
static void check_combine(void) {
    const unsigned n_embd = 5120;
    const unsigned n_layer = 40;
    const unsigned n_slots = n_layer * DS4_TP_GATES_PER_LAYER;
    ds4_tp tp = {.rank = 0, .n_ranks = NRANKS, .n_layer = n_layer,
        .n_slots = n_slots, .n_embd = n_embd,
        .vec_bytes = (uint64_t)n_embd * sizeof(float)};
    tp_slab_layout(&tp);
    uint8_t *slab = calloc(1, ds4_tp_slab_bytes_for(n_layer, n_embd, NRANKS));
    tp.slab = slab;
    const unsigned layer = 3, gate = 1;
    float *dst = (float *)(slab + ds4_tp_slab_in_offset(&tp, layer, gate));
    for (unsigned i = 0; i < n_embd; i++) dst[i] = 0.25f * (float)i + 1.0f; /* peer 1 */
    for (unsigned pr = 2; pr < NRANKS; pr++) {
        float *src = (float *)(slab + ds4_tp_slab_in_offset_peer(&tp, pr, layer, gate));
        for (unsigned i = 0; i < n_embd; i++) src[i] = 0.25f * (float)i + (float)pr;
    }
    ds4_tp_combine_slab(&tp, layer, gate);
    for (unsigned i = 0; i < n_embd; i++) {
        float expect = 0.25f * (float)i + 1.0f + 0.25f * (float)i + 2.0f +
                       0.25f * (float)i + 3.0f;
        assert(fabsf(dst[i] - expect) < 1e-3f);
    }
    free(slab);
    puts("4-way N-way combine: block 0 sums all peers' partials: PASS");
}

int main(void) {
    check_mesh();
    check_batch_mesh();
    check_combine();
    return 0;
}
