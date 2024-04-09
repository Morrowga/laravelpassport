<?php

use App\Models\User;


function checkScopes(User $user, $requiredScope)
{
    return $user->hasPermission($requiredScope);
}
