#include <stdlib.h>

#include <rte_malloc.h>
#include "agiep_vring_split_predict.h"
#include "agiep_logs.h"

/**
 *
 * @param predict
 * @param avail
 * @param avail_idx
 * @param last_avail_idx
 * @param seg
 * @return ret: nb_seg , ret < 0 : fatal error
 */
int vring_split_predict_desc(struct agiep_vring_split_predict *predict,
	const uint16_t *avail, uint16_t avail_idx, uint16_t last_avail_idx,
	struct desc_seg *seg)
{
	uint16_t num;
	uint16_t desc_idx;
	uint16_t next_desc_idx;
	int k = 0;
	int diff;

	num = predict->num;

	desc_idx = avail[last_avail_idx % num];
	next_desc_idx = avail[(avail_idx - 1) % num];
	next_desc_idx += predict->avg_size;
	next_desc_idx = next_desc_idx % num;
	diff = next_desc_idx - desc_idx;
	// 如果next_desc_idx加上预测值以后大于desc_idx，则认为是总长度超过num
	if (diff > 0 && diff < predict->avg_size)
		next_desc_idx = desc_idx;
	seg[k].id = desc_idx;
	if (desc_idx < next_desc_idx) {
		seg[k].len = next_desc_idx - desc_idx + 1;
	} else {
		seg[k].len = num - desc_idx;
		k++;

		seg[k].id = 0;
		seg[k].len = next_desc_idx + 1;
	}

	return k + 1;
}
/**
 *
 * @param predict
 * @param desc_idx
 * @param seg
 * @return ret == 1 || ret == 2
 */
int vring_split_predict_next(struct agiep_vring_split_predict *predict,
		uint16_t desc_idx, struct desc_seg *seg)
{
	int predict_size = predict->avg_size;
	if (desc_idx + predict_size > predict->num) {
		seg[0].id = desc_idx;
		seg[0].len = predict->num - desc_idx;

		seg[1].id = 0;
		seg[1].len = predict_size - seg[0].len;
		return 2;
	}

	seg[0].id = desc_idx;
	seg[0].len = predict_size;
	return 1;
}

int vring_split_predict_init(struct agiep_vring_split_predict *predict, uint16_t num)
{
	predict->num = num;
	predict->avg_size = DEFAULT_AVG_SIZE;
	return 0;
}
