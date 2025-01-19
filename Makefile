# 컴파일러 설정
CC = gcc

# 컴파일 옵션 설정
CFLAGS = -Wall -Wextra -O2

# 링크 옵션 설정
LDFLAGS = -lpcap

# 타겟 실행 파일 이름
TARGET = beacon-flood

# 소스 파일
SRC = beacon-flood.c

# 기본 타겟: 실행 파일 생성
$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

# 'make clean' 명령어로 생성된 파일 삭제
clean:
	rm -f $(TARGET)

