# 文件保护者编译配置
CXX = g++
# 编译选项：
CXXFLAGS = -Wall -fPIC -std=c++17 -O2 -pthread -I./ol/include
# 动态库链接参数：
LDFLAGS = -shared -fPIC -Wl,--whole-archive ./ol/lib/libol.a -Wl,--no-whole-archive -ldl -pthread

# 目标文件：
SO_FILE = libfile_protector.so

# 测试文件路径
TEST_DIR = ../test

# 编译动态库
all: $(SO_FILE) $(TEST_DIR)/test_norm $(TEST_DIR)/test_prot

# 动态库编译
$(SO_FILE): File_Protector.o
	$(CXX) $(LDFLAGS) -o $@ $^
	@echo "✅ 动态库编译完成：$@"

File_Protector.o: File_Protector.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

# 非白名单测试程序
$(TEST_DIR)/test_norm: $(TEST_DIR)/test_norm.cpp
	$(CXX) -std=c++17 -o $@ $< -pthread
	@echo "✅ 非白名单测试程序编译完成：$@"

# 白名单测试程序
$(TEST_DIR)/test_prot: $(TEST_DIR)/test_prot.cpp
	$(CXX) -std=c++17 -o $@ $< -pthread
	@echo "✅ 白名单测试程序编译完成：$@"

# 测试目标
test: all
	@echo "========================================"
	@echo "🔍 第一步：创建测试文件"
	@touch $(TEST_DIR)/prot.txt $(TEST_DIR)/norm.txt
	@echo "✅ 测试文件创建完成"

	@echo "========================================"
	@echo "🔍 第二步：测试非白名单进程（test_norm）"
	LD_PRELOAD=./$(SO_FILE) $(TEST_DIR)/test_norm

	@echo "========================================"
	@echo "🔍 第三步：测试白名单进程（test_prot）"
	LD_PRELOAD=./$(SO_FILE) $(TEST_DIR)/test_prot

	@echo "========================================"
	@echo "🔍 第四步：查看拦截日志"
	@tail -20 file_protector.log || echo "日志文件暂未生成"

# 清理
clean:
	rm -f *.o *.so $(TEST_DIR)/test_norm $(TEST_DIR)/test_prot
	rm -f ./file_protector.log
	@echo "✅ 清理完成"