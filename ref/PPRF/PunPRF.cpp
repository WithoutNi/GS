#include "PunPRF.h"

PunPRF::PunPRF(const unsigned char* seed,uint32_t layer){
    unsigned char buf[KEY_SIZE+1]={0};
    memcpy(buf,seed,KEY_SIZE);
    buf[KEY_SIZE]=(unsigned char)layer;
    shake256(root_key,KEY_SIZE,buf,KEY_SIZE+1);
}

void PunPRF::getkey(unsigned char kpi[KEY_SIZE]){
    memcpy(kpi,root_key,KEY_SIZE);
}

void PunPRF::Punc(unsigned long long point, int depth)
{
    unsigned char output_keys[2][KEY_SIZE];
    unsigned char current_key[KEY_SIZE];
    memcpy(current_key, root_key, KEY_SIZE);

    for (int i = 0; i < depth; ++i)
    {
        aes_prg(current_key, output_keys);

        if ((point >> (depth - i - 1)) & 1)
        {
            // Right child
            find_or_create_node(point >> (depth - i - 1), i + 1,prefix_forest)->key;
            memcpy(current_key, output_keys[1], KEY_SIZE);
        }
        else
        {
            // Left child
            find_or_create_node(point >> (depth - i - 1), i + 1,prefix_forest)->key;
            memcpy(current_key, output_keys[0], KEY_SIZE);
        }
    }

    // Mark the punctured node
    Node *punctured_node = find_or_create_node(point, depth,prefix_forest);
    memset(punctured_node->key, 0, KEY_SIZE); // Invalidate key
    punctured_node->is_punctured = true;
}

unsigned char* PunPRF::Eval(unsigned long long point, int depth)
{
    unsigned char current_key[KEY_SIZE];
    memcpy(current_key, root_key, KEY_SIZE);

    for (int i = 0; i < depth; ++i)
    {
        unsigned char output_keys[2][KEY_SIZE];
        aes_prg(current_key, output_keys);

        Node *node = find_or_create_node(point >> (depth - i - 1), i + 1,prefix_forest);

        // Check if the node is punctured
        if (node->is_punctured)
        {
            // std::cerr << "Error: Point "<<point<< " is punctured." << std::endl;
            return NULL;
        }

        if ((point >> (depth - i - 1)) & 1)
        {
            memcpy(current_key, output_keys[1], KEY_SIZE);
        }
        else
        {
            memcpy(current_key, output_keys[0], KEY_SIZE);
        }
    }

    unsigned char* result=new unsigned char[KEY_SIZE];
    memcpy(result, current_key, KEY_SIZE);
    return result;
}

unsigned char* PunPRF::GetMsg(unsigned char* k, unsigned long long i, int n) {
    (void)k; // 未使用参数，保留以兼容接口
    unsigned long long current_prefix = 0; // 初始化为空前缀

    for (int j = 1; j <= n; ++j) {
        unsigned long long prefix_left = current_prefix << 1; // current_prefix||0

        // 计算左子树中未被穿孔的叶子节点数
        unsigned long long mu = 0; // 左子树中穿孔的叶子节点数
        unsigned long long total_leaves = 1ULL << (n - j); // 当前层的叶子节点总数

        // 遍历左子树的所有叶子节点，统计穿孔的节点数
        for (unsigned long long p = 0; p < total_leaves; ++p) {
            unsigned long long leaf_prefix = (prefix_left << (n - j)) | p;
            Node* leaf_node = find_or_create_node(leaf_prefix, n, prefix_forest);
            if (leaf_node->is_punctured) {
                mu++;
            }
        }

        unsigned long long nu = total_leaves - mu; // 左子树中未被穿孔的叶子节点数

        if (i <= nu) {
            // 选择左子树
            current_prefix = prefix_left;
        } else {
            // 选择右子树
            current_prefix = prefix_left | 1;
            i -= nu; // 调整i，跳过左子树中未被穿孔的节点
        }
    }

    printf("re=%llu\n",current_prefix);
    // 将current_prefix转换为n位二进制数组（小端序）
    unsigned char* result = new unsigned char[KEY_SIZE]();
    for (int bit = 0; bit < n; ++bit) {
        if (current_prefix & (1ULL << bit)) {
            int byte_pos = bit / 8;
            int bit_pos = bit % 8;
            result[byte_pos] |= (unsigned char)(1 << bit_pos);
        }
    }

    return result;
}

void aes_prg(const unsigned char *input_key, unsigned char output_keys[2][KEY_SIZE])
{
    AES_KEY aes_key;
    AES_set_encrypt_key(input_key, 128, &aes_key);

    unsigned char counter[KEY_SIZE] = {0};

    // Generate first output key
    AES_encrypt(counter, output_keys[0], &aes_key);

    // Increment counter for the second output key
    counter[KEY_SIZE - 1] = 1;
    AES_encrypt(counter, output_keys[1], &aes_key);
}

Node *find_or_create_node(unsigned long long prefix, int depth,std::map<unsigned long long, Node>& prefix_forest)
{
    (void)depth;
    if (prefix_forest.find(prefix) == prefix_forest.end())
    {
        Node new_node;
        memset(new_node.key, 0, KEY_SIZE);
        new_node.is_punctured = false;
        prefix_forest[prefix] = new_node;
    }
    return &prefix_forest[prefix];
}