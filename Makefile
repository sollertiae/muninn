CXX = clang++
CXXFLAGS = -Wall -Wextra -std=c++17 -I/opt/homebrew/opt/libsodium/include
LDFLAGS = -L/opt/homebrew/opt/libsodium/lib -lsodium
SRCS = main.cpp vault.cpp memory.cpp

muninn: $(SRCS)
	$(CXX) $(CXXFLAGS) -o muninn $(SRCS) $(LDFLAGS)

debug: $(SRCS)
	$(CXX) $(CXXFLAGS) -fsanitize=address,undefined -o muninn_debug $(SRCS) $(LDFLAGS)

clean:
	rm -f muninn muninn_debug