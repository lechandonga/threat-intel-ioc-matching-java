package com.github.lechandonga.threatinteliocmatchingjava.tests.coverage;

import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.AfterTestExecutionCallback;
import org.junit.jupiter.api.extension.TestExecutionExceptionHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 测试覆盖日志扩展：按 {@link BusinessTest} 标注的业务分组，
 * 在控制台打印“覆盖了哪些业务、每个业务包含哪些用例、通过/失败情况”，
 * 让 {@code mvn test} 日志本身即可说明覆盖范围。
 */
public class BusinessCoverageExtension implements BeforeAllCallback, BeforeEachCallback,
        AfterAllCallback, AfterTestExecutionCallback {

    private static final Logger log = LoggerFactory.getLogger("BUSINESS-COVERAGE");

    private record Case(String name, boolean failed) {
    }

    @Override
    public void beforeAll(ExtensionContext context) {
        BusinessTest annotation = context.getRequiredTestClass().getAnnotation(BusinessTest.class);
        if (annotation != null) {
            log.info("==== 业务覆盖 [{}] 开始 ====", annotation.value());
        }
    }

    @Override
    public void beforeEach(ExtensionContext context) {
        BusinessTest annotation = context.getRequiredTestClass().getAnnotation(BusinessTest.class);
        if (annotation != null) {
            log.info("[{}] >> 用例: {}", annotation.value(), context.getDisplayName());
        }
    }

    @Override
    public void afterAll(ExtensionContext context) {
        BusinessTest annotation = context.getRequiredTestClass().getAnnotation(BusinessTest.class);
        if (annotation == null) {
            return;
        }
        List<Case> cases = store(context).computeIfAbsent(
                context.getRequiredTestClass().getName(), k -> java.util.Collections.synchronizedList(new ArrayList<>()));
        long passed = cases.stream().filter(c -> !c.failed()).count();
        long failed = cases.size() - passed;
        log.info("==== 业务覆盖 [{}] 结束: 共 {} 个用例, 通过 {}, 失败 {} ====",
                annotation.value(), cases.size(), passed, failed);
    }

    @Override
    public void afterTestExecution(ExtensionContext context) {
        BusinessTest annotation = context.getRequiredTestClass().getAnnotation(BusinessTest.class);
        if (annotation != null) {
            store(context).computeIfAbsent(context.getRequiredTestClass().getName(),
                            k -> java.util.Collections.synchronizedList(new ArrayList<>()))
                    .add(new Case(context.getDisplayName(),
                            context.getExecutionException().isPresent()));
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, List<Case>> store(ExtensionContext context) {
        ExtensionContext.Store store = context.getRoot().getStore(
                ExtensionContext.Namespace.create(BusinessCoverageExtension.class));
        return (Map<String, List<Case>>) store
                .getOrComputeIfAbsent("cases", key -> new ConcurrentHashMap<String, List<Case>>());
    }
}
