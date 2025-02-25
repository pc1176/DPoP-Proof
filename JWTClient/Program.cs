// See https://aka.ms/new-console-template for more information
using JWTClient.Services;

public class Program
{
    static async Task Main(string[] args)
    {
        var apiClient = new ApiClient("http://localhost:5086");

        // Login
        var loggedIn = await apiClient.LoginAsync("username", "password");

        if (loggedIn)
        {
            var products = await apiClient.GetProductsAsync();
            foreach (var product in products)
            {
                Console.WriteLine($"Product: {product.DeviceName}, Price: {product.DeviceType}");
            }
        }


        Console.ReadLine();
    }
}
