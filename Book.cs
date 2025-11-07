namespace BookNookAPI 
{
    public class Book
    {
        public int Id { get; set; }
        public string Title { get; set; }
        public string Genre { get; set; }
        public string Description { get; set; }

        // Foreign key
        public int AuthorId { get; set; }
        public Author Author { get; set; }
        
        // Initialize the list
        public List<Review> Reviews { get; set; } = new List<Review>(); 
    }

    public class Author
    {
        public int Id { get; set; }
        public string Name { get; set; }

        // Initialize the list
        public List<Book> Books { get; set; } = new List<Book>();
    }

    public class Review
    {
        public int Id { get; set; }
        public string ReviewText { get; set; }
        public int Rating { get; set; } 

        // Foreign keys
        public int BookId { get; set; }
        public Book Book { get; set; }
    }
}
