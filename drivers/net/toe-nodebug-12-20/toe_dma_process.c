








#define dma_init

static void toe_dma_job_init(struct rte_mempool *mp __rte_unused,
	void *opaque, void *obj, unsigned int idx)
{
	struct toe_sync_dma_job *job = obj;
	struct toe_dma_info *dma = opaque;
	memset(job, 0, sizeof(*job));
	//job->t_dma = dma;
	job->job = &dma->qjobs[idx];
	job->job->flags = RTE_QDMA_JOB_SRC_PHY | RTE_QDMA_JOB_DEST_PHY;
}

static int toe_dma_job_pool_init(struct toe_dma_info *dma) 
{
	char name[RTE_MEMPOOL_NAMESIZE];
	struct rte_mempool *mp;
	uint32_t elt_size;

	dma->qjobs = rte_calloc(NULL, dma->job_cnt, sizeof(struct rte_qdma_job), RTE_CACHE_LINE_SIZE);

	if (!dma->qjobs)
		return -rte_errno;

	snprintf(name, sizeof(name),
			"toe_dma_j_%d_%lx", dma->vf, rte_rdtsc());

	elt_size = sizeof(struct toe_sync_dma_job);
/*
	if (elt_size < sizeof(struct agiep_async_dma_group))
		elt_size = sizeof(struct agiep_async_dma_group);
*/
	// 目前只有一个NUMA: 0
	mp = rte_mempool_create(name, dma->job_cnt,
			elt_size,
			DMA_JOB_CACHE_SIZE, 0, NULL, NULL, toe_dma_job_init,
			dma, SOCKET_ID_ANY, 0);

	if (mp == NULL) {
		RTE_LOG(ERR, PMD,
				"mempool %s create failed: %d", name, rte_errno);
		return -rte_errno;
	}

	dma->jpool = mp;
	return 0;
}

static void toe_dma_job_pool_free(struct toe_dma_info *dma) 
{
	if (dma->qjobs)
		rte_free(dma->qjobs);
	if (dma->jpool) {
		rte_mempool_free(dma->jpool);
		dma->jpool = NULL;
	}
}

static int toe_qdma_init(int qdma_dev_id)
{
	struct rte_qdma_config qdma_config;
	struct rte_qdma_info dev_conf;
	char name[RTE_MEMPOOL_NAMESIZE];
	int ret;
	int i = 0;

	/* Configure QDMA to use HW resource - no virtual queues */
	qdma_config.max_hw_queues_per_core = TOE_QDMA_MAX_HW_QUEUES_PER_CORE;
	qdma_config.fle_queue_pool_cnt = TOE_QDMA_FLE_POOL_QUEUE_COUNT;
	qdma_config.max_vqs = TOE_QDMA_MAX_VQS;

	dev_conf.dev_private = (void *)&qdma_config;
	ret = rte_qdma_configure(qdma_dev_id, &dev_conf);

	if (ret && ret != -EBUSY) {
		RTE_LOG(ERR, PMD, "Failed to configure DMA\n");
		goto done;
	}

	ret = rte_qdma_start(qdma_dev_id);
	if (ret) {
		RTE_LOG(ERR, PMD, "Failed to start DMA\n");
		goto done;
	}

done:
	return qdma_dev_id;
	/*
error:
	//rte_ring_free(GC_ring);
qdma_error:
	return -EINVAL;
	*/
}

static inline int toe_qdma_queue_setup(int dma_id,int lcore_id, uint32_t vq_flags)
{
	struct rte_qdma_queue_config qdma_config;
	qdma_config.lcore_id = lcore_id;
	qdma_config.flags = vq_flags;
	qdma_config.rbp = NULL;
	return rte_qdma_queue_setup(dma_id, -1, &qdma_config);
}

static void toe_dma_hwq_init(int pf, int vf)
{
	int lcore;
	int i;
	struct toe_dma_hwq *hwq;
	struct rte_qdma_rbp *rbp;
	unsigned int portid = agiep_get_portid();
	uint32_t vq_flags = RTE_QDMA_VQ_EXCLUSIVE_PQ | RTE_QDMA_VQ_FD_LONG_FORMAT
		| RTE_QDMA_VQ_FD_SG_FORMAT;

	RTE_LCORE_FOREACH(lcore) {
		hwq = &tdma_hwq[lcore];
		hwq->lcore_id = lcore;
		hwq->id = tqdma_dev_id;
		hwq->vq = toe_qdma_queue_setup(tqdma_dev_id, lcore, vq_flags);
		assert(hwq->vq >= 0);
		//printf("%s-%d: hwq->vq:%d\n",__func__,__LINE__,hwq->vq);
		//for (i = 0; i < pf_num; i++) {
			//pf = pfs[i];
			//for (vf = 0; vf < vf_num[i]; vf++) {
				//rbp = &hwq->R_rbp[pf][vf];
				rbp = &hwq->R_rbp;
				memset(rbp, 0, sizeof(struct rte_qdma_rbp));
				rbp->enable = 1;

				if (vq_flags & RTE_QDMA_VQ_FD_LONG_FORMAT)
					rbp->use_ultrashort = 0;
				else
					rbp->use_ultrashort = 1;
				rbp->srbp = 1;
				rbp->drbp = 0;
				rbp->sportid = portid;
				rbp->spfid = pf;
				rbp->svfid = vf;

				rbp = &hwq->W_rbp;
				memset(rbp, 0, sizeof(struct rte_qdma_rbp));
				rbp->enable = 1;

				if (vq_flags & RTE_QDMA_VQ_FD_LONG_FORMAT)
					rbp->use_ultrashort = 0;
				else
					rbp->use_ultrashort = 1;
				rbp->srbp = 0;
				rbp->drbp = 1;
				rbp->dportid = portid;
				rbp->dpfid = pf;
				rbp->dvfid = vf;
			//}
		//}

		rte_compiler_barrier();
		hwq->enable = 1;
	}
}

int toe_dma_init(struct toe_engine *toe_eg)
{
	struct toe_dma_info *dma;
	//cpu_set_t mask;
	//uint16_t lcoreid = 0;
	const char *thread_name = "toe_ctrl_loop";
	const char *cq_thread_name = "toe_cq_loop";
	int ret;

	dma = rte_calloc(NULL, 1, sizeof(struct toe_dma_info), RTE_CACHE_LINE_SIZE);
	if (dma == NULL)
		return -1;
	toe_eg->t_dma = dma;
	dma->id = tqdma_dev_id;
	dma->job_cnt = JOB_POOL_NUM;
	dma->pf = toe_eg->pf;
	dma->vf = toe_eg->vf;

	if (toe_dma_job_pool_init(dma))
		goto failed;
	
	tqdma_dev_id = toe_qdma_init(tqdma_dev_id);
	assert(tqdma_dev_id >= 0);

	toe_dma_hwq_init(toe_eg->pf, toe_eg->vf);
#if 0
	assert(TOE_CTRL_thread == 0);
	ret = pthread_create(&TOE_CTRL_thread, NULL, toe_ctrl_dma_loop, toe_eg);
	if (ret) {
		printf("%s-%d toe ctrl thread create failed!\n", __func__, __LINE__);
		goto failed;
	}
	ret = pthread_setname_np(TOE_CTRL_thread, thread_name);
	if (ret)
		goto failed;
	#endif
/*
	lcoreid = rte_lcore_id();
	CPU_ZERO(&mask);
	CPU_SET(lcoreid, &mask);
	printf("@@@ %s-%d: lcore:%d\n",__func__,__LINE__,lcoreid);
	ret = pthread_setaffinity_np(TOE_CTRL_thread, sizeof(mask), &mask);
	if (ret < 0)
		RTE_LOG(ERR, PMD, "toe: set TOE_CTRL_thread cpu id fail: %d\n", ret);
*/

	#if 0
	assert(TOE_DATA_CQ_thread == 0);
	ret = pthread_create(&TOE_DATA_CQ_thread, NULL, toe_data_cq_dma_loop, toe_eg);
	if (ret) {
		printf("%s-%d toe data cq thread create failed!\n", __func__, __LINE__);
		goto failed;
	}
	ret = pthread_setname_np(TOE_DATA_CQ_thread, cq_thread_name);
	if (ret)
		goto failed;
#endif

	return 0;

failed:

	if (dma)
		rte_free(dma);
	return -1;
}

static void toe_qdma_fini(int qdma_dev_id)
{
	rte_rawdev_stop(qdma_dev_id);
	rte_rawdev_close(qdma_dev_id);
}

void toe_dma_hwq_destroy(void)
{
	int lcore;
	struct toe_dma_hwq *hwq;
	for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
		hwq = &tdma_hwq[lcore];		
		if (!hwq->enable)
			continue;
		rte_rawdev_queue_release(hwq->id, hwq->vq);
	}
}

void toe_dma_fini(void)
{
	toe_dma_hwq_destroy();
	toe_qdma_fini(tqdma_dev_id);
}

void toe_dma_reset(struct toe_engine *toe_eg)
{
	int i, ret = 0;
	uint64_t now = rte_rdtsc()/rte_get_tsc_hz();
	uint64_t last = now;
	//printf("~~ %s-%d: dma reset start \n", __func__,__LINE__);
	do {
		now = rte_rdtsc()/rte_get_tsc_hz();
		ret = toe_dma_dequeue(toe_eg);
		if (ret > 0)
			last = now;
	}while ((now - last) < 2);

	for (i = 0; i < toe_eg->t_dev->ctrl_queues; i++) {

		toe_eg->ctl_rx_vring[i]->rq_info.local_head = 0;
		toe_eg->ctl_rx_vring[i]->rq_info.pre_head = 0;
		toe_eg->ctl_rx_vring[i]->rq_info.head = 0;
		toe_eg->ctl_rx_vring[i]->rq_info.tail = 0;


		toe_eg->ctl_rx_vring[i]->cq_info.pre_head = 0;
		toe_eg->ctl_rx_vring[i]->cq_info.head = 0;
		toe_eg->ctl_rx_vring[i]->cq_info.pre_tail = 0;
		toe_eg->ctl_rx_vring[i]->cq_info.tail = 0;
		toe_eg->ctl_rx_vring[i]->cq_info.cq_compl = 1;
		//printf("%s-%d: ctrl rq cq set 0!\n",__func__,__LINE__);

		ret = rte_atomic16_read(&toe_eg->ctl_rx_vring[i]->rq_info.wait_head_num);
		if (ret != 0) {
			printf("%s-%d: ctrl rq vring wait_head_num:%d, it's should be 0!\n",__func__,__LINE__,ret);
			
			rte_atomic16_set(&toe_eg->ctl_rx_vring[i]->rq_info.wait_head_num, 0);
		}
		
		ret = rte_atomic16_read(&toe_eg->ctl_rx_vring[i]->cq_info.wait_tail_num);
		if (ret != 0) {
			printf("%s-%d: ctrl cq vring wait_tail_num:%d, it's should be 0!\n",__func__,__LINE__,ret);
			
			rte_atomic16_set(&toe_eg->ctl_rx_vring[i]->cq_info.wait_tail_num, 0);
		}
	}

	for (i = 0; i < toe_eg->t_dev->data_queues; i++) {
		toe_eg->data_rx_vring[i]->rq_info.pre_head = 0;
		toe_eg->data_rx_vring[i]->rq_info.head = 0;
		toe_eg->data_rx_vring[i]->rq_info.real_tail = 0;
		toe_eg->data_rx_vring[i]->rq_info.tail = 0;

		toe_eg->data_rx_vring[i]->cq_info.pre_head = 0;
		toe_eg->data_rx_vring[i]->cq_info.head = 0;
		toe_eg->data_rx_vring[i]->cq_info.pre_tail = 0;
		toe_eg->data_rx_vring[i]->cq_info.tail = 0;
		toe_eg->data_rx_vring[i]->cq_info.cq_compl = 1;

		toe_eg->data_tx_vring[i]->rq_info.pre_head = 0;
		toe_eg->data_tx_vring[i]->rq_info.head = 0;
		toe_eg->data_tx_vring[i]->rq_info.real_tail = 0;
		toe_eg->data_tx_vring[i]->rq_info.tail = 0;

		toe_eg->data_tx_vring[i]->cq_info.pre_head = 0;
		toe_eg->data_tx_vring[i]->cq_info.head = 0;
		toe_eg->data_tx_vring[i]->cq_info.tail = 0;
		toe_eg->data_tx_vring[i]->cq_info.cq_compl = 1;
		
	printf("%s-%d: data rq set 0!\n",__func__,__LINE__);
	}

	return;
}

