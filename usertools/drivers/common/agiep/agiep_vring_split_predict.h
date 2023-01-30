#ifndef RTE_AGIEP_VRING_SPLIT_PREDICT_H__
#define RTE_AGIEP_VRING_SPLIT_PREDICT_H__

#define DEFAULT_AVG_SIZE 2
#define DEFAULT_GAP 4

struct desc_seg {
	uint16_t id;
	uint16_t len;
};

// 40 byte
struct agiep_vring_split_predict {
	uint16_t num;
	uint16_t avg_size;
} __attribute__((__packed__));

int vring_split_predict_desc(struct agiep_vring_split_predict *predict,
	const uint16_t *avail, uint16_t avail_idx, uint16_t last_avail_idx,
	struct desc_seg *seg);

int vring_split_predict_next(struct agiep_vring_split_predict *predict, uint16_t desc_idx, struct desc_seg *seg);

int vring_split_predict_init(struct agiep_vring_split_predict *predict, uint16_t num);


#endif
