package com.prgrms.devcourse;

import static java.util.concurrent.CompletableFuture.*;

import java.util.concurrent.CompletableFuture;

public class ThreadLocalApp {

    final static ThreadLocal<Integer> threadLocalValue = new ThreadLocal<>();

    public static void main(String[] args) {
        System.out.println(getCurrentThreadName() + " ### main set value = 1");
        threadLocalValue.set(1);

        // main thread에서 실행
        a();    // main ### a() get value = 1
        b();    // main ### b() get value = 1

        CompletableFuture<Void> task = runAsync(() -> {    // main이 아닌 다른 스레드에서 코드 블록 실행
            a();
            b();
        });

        task.join();    // 코드 블록이 실행 완료될 때까지 대기 걸기
        /* 출력
        ForkJoinPool.commonPool-worker-1 ### a() get value = null
        ForkJoinPool.commonPool-worker-1 ### b() get value = null
        ThreadLocal 변수는 스레드마다 독립적인 변수, 서로 다른 스레드의 로컬 변수를 참조할 수 없음.
         */
    }

    public static void a() {
        Integer value = threadLocalValue.get();
        System.out.println(getCurrentThreadName() + " ### a() get value = " + value);
    }

    public static void b() {
        Integer value = threadLocalValue.get();
        System.out.println(getCurrentThreadName() + " ### b() get value = " + value);
    }

    public static String getCurrentThreadName() {
        // 코드가 실행되고 있는 스레드가 어떤 스레드인지
        return Thread.currentThread().getName();
    }
}
