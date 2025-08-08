use lib::*;

#[test]
fn test_add() {
    let result = add(2, 2);
    assert_eq!(result, 4);
    
    let result = add(0, 0);
    assert_eq!(result, 0);
    
    let result = add(100, 200);
    assert_eq!(result, 300);
}

#[test]
fn test_add_edge_cases() {
    // 测试大数值
    let result = add(usize::MAX - 1, 0);
    assert_eq!(result, usize::MAX - 1);
    
    // 测试边界值
    let result = add(1, usize::MAX - 1);
    assert_eq!(result, usize::MAX);
}
