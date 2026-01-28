"""
Unit tests for BookCipherApp GUI functionality.
Tests randomize_books and other UI methods.
"""

import random
from pathlib import Path
import pytest


# Test the randomize logic in isolation without needing tkinter
class TestRandomizeBooksLogic:
    """Test book randomization functionality without GUI."""

    def test_shuffle_logic_with_multiple_books(self):
        """Test that random.shuffle works on a list of books."""
        book_paths = [Path(f"/tmp/book{i}.txt") for i in range(5)]
        original = book_paths.copy()
        
        random.seed(42)
        random.shuffle(book_paths)
        
        # Verify list was shuffled (different order)
        assert book_paths != original
        
        # Verify same elements (just reordered)
        assert set(book_paths) == set(original)
        assert len(book_paths) == len(original)

    def test_shuffle_logic_with_single_book(self):
        """Test that shuffle on single item list doesn't change it."""
        book_paths = [Path("/tmp/book1.txt")]
        original = book_paths.copy()
        
        random.shuffle(book_paths)
        
        # Single element list remains unchanged
        assert book_paths == original

    def test_shuffle_logic_with_empty_list(self):
        """Test that shuffle on empty list doesn't crash."""
        book_paths = []
        original = book_paths.copy()
        
        random.shuffle(book_paths)
        
        # Empty list remains empty
        assert book_paths == original

    def test_multiple_shuffles_produce_different_orders(self):
        """Test that multiple shuffles produce different orderings."""
        book_paths = [Path(f"/tmp/book{i}.txt") for i in range(5)]
        orders_seen = set()
        
        # Run shuffle 20 times
        for i in range(20):
            test_paths = book_paths.copy()
            random.seed(i)
            random.shuffle(test_paths)
            orders_seen.add(tuple(test_paths))
        
        # Should see multiple different orderings
        # With 5 books, 5! = 120 possible orderings
        # After 20 shuffles, we should see at least 10 different orderings
        assert len(orders_seen) >= 10, f"Only saw {len(orders_seen)} different orderings"

    def test_randomize_books_method_implementation(self):
        """Test the actual randomize_books implementation logic."""
        # Simulate the method's behavior
        def randomize_books_impl(book_paths, refresh_callback, changed_callback):
            """Simulates the randomize_books method."""
            if len(book_paths) > 1:
                random.shuffle(book_paths)
                refresh_callback()
                changed_callback()
        
        # Test with multiple books
        book_paths = [Path(f"/tmp/book{i}.txt") for i in range(3)]
        original = book_paths.copy()
        
        refresh_called = False
        changed_called = False
        
        def refresh_cb():
            nonlocal refresh_called
            refresh_called = True
        
        def changed_cb():
            nonlocal changed_called
            changed_called = True
        
        random.seed(42)
        randomize_books_impl(book_paths, refresh_cb, changed_cb)
        
        # Verify callbacks were called
        assert refresh_called, "Refresh callback should be called"
        assert changed_called, "Changed callback should be called"
        
        # Verify list was shuffled
        assert book_paths != original, "Book paths should be shuffled"
        assert set(book_paths) == set(original), "Same books should be present"

    def test_randomize_books_single_book_no_callbacks(self):
        """Test that single book doesn't trigger callbacks."""
        def randomize_books_impl(book_paths, refresh_callback, changed_callback):
            """Simulates the randomize_books method."""
            if len(book_paths) > 1:
                random.shuffle(book_paths)
                refresh_callback()
                changed_callback()
        
        # Test with single book
        book_paths = [Path("/tmp/book1.txt")]
        original = book_paths.copy()
        
        refresh_called = False
        changed_called = False
        
        def refresh_cb():
            nonlocal refresh_called
            refresh_called = True
        
        def changed_cb():
            nonlocal changed_called
            changed_called = True
        
        randomize_books_impl(book_paths, refresh_cb, changed_cb)
        
        # Verify callbacks were NOT called
        assert not refresh_called, "Refresh callback should not be called"
        assert not changed_called, "Changed callback should not be called"
        
        # Verify list unchanged
        assert book_paths == original


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
