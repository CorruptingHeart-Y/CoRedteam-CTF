import chromadb

# 连接到本地大脑
client = chromadb.PersistentClient(path="./co_redteam_memory")

# 获取所有脑区（集合）
collections = client.list_collections()
print("🧠 当前系统内存在以下记忆集合:")
for c in collections:
    print(f" - {c.name}")

# 假设长期记忆集合叫 'evolution_memory' (请根据上面打印的实际名字修改)
target_collection_name = "vulnerability_patterns"

try:
    memory_collection = client.get_collection(target_collection_name)
    records = memory_collection.get()
    
    total_records = len(records['ids'])
    print(f"\n📚 [{target_collection_name}] 中共存有 {total_records} 条实战经验：\n")
    
    for i in range(total_records):
        print(f"💡 ID: {records['ids'][i]}")
        print(f"📜 经验总结:\n{records['documents'][i]}")
        print("-" * 50)
        
except Exception as e:
    print(f"\n⚠️ 无法读取 {target_collection_name}，它可能还没被创建，或者名字不对。错误: {e}")