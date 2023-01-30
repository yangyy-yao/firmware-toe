#ifndef TCP_STREAM_QUEUE
#define TCP_STREAM_QUEUE

#include <stdint.h>

/* Lock definitions for stream queue */
#if LOCK_STREAM_QUEUE

#define SQ_LOCK_INIT(lock, errmsg, action);     \
    if (pthread_mutex_init(lock, NULL)) {       \
        perror("pthread_mutex_init" errmsg);    \
        action;                                 \
    }
#define SQ_LOCK_DESTROY(lock)   pthread_mutex_destroy(lock)
#define SQ_LOCK(lock)           rte_spinlock_lock(lock)
#define SQ_UNLOCK(lock)         rte_spinlock_unlock(lock)

#else /* LOCK_STREAM_QUEUE */
#define SQ_LOCK_INIT(lock, errmsg, action)  (void) 0
#define SQ_LOCK_DESTROY(lock)   (void) 0
#define SQ_LOCK(lock)           (void) 0
#define SQ_UNLOCK(lock)         (void) 0
#endif /* LOCK_STREAM_QUEUE */

/*---------------------------------------------------------------------------*/
typedef struct stream_queue* stream_queue_t;
/*---------------------------------------------------------------------------*/
typedef struct stream_queue_int
{
    struct tcp_stream **array;
    int size;

    int first;
    int last;
    int count;

} stream_queue_int;
/*---------------------------------------------------------------------------*/
stream_queue_int * 
CreateInternalStreamQueue(int size);
/*---------------------------------------------------------------------------*/
void 
DestroyInternalStreamQueue(stream_queue_int *sq);
/*---------------------------------------------------------------------------*/
int 
StreamInternalEnqueue(stream_queue_int *sq, struct tcp_stream *stream);
/*---------------------------------------------------------------------------*/
struct tcp_stream *
StreamInternalDequeue(stream_queue_int *sq);
/*---------------------------------------------------------------------------*/
stream_queue_t 
CreateStreamQueue(int size);
/*---------------------------------------------------------------------------*/
void 
DestroyStreamQueue(stream_queue_t sq);
/*---------------------------------------------------------------------------*/
int 
StreamEnqueue(stream_queue_t sq, struct tcp_stream *stream);
/*---------------------------------------------------------------------------*/
struct tcp_stream *
StreamDequeue(stream_queue_t sq);
/*---------------------------------------------------------------------------*/
int 
StreamQueueIsEmpty(stream_queue_t sq);
/*---------------------------------------------------------------------------*/

#endif /* TCP_STREAM_QUEUE */
