use App\Http\Requests\CustomLoginRequest;
use Laravel\Fortify\Fortify;

public function boot()
{
    // Ganti login request
    Fortify::authenticateUsing(function (CustomLoginRequest $request) {
        $request->authenticate();
        return Auth::user();
    });
}
